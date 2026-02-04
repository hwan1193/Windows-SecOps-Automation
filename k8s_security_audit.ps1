param(
    [string]$Namespace,
    [string]$OutDir,
    [int]$TrivyScanLimit = 0,
    [string]$KubectlPath = $(if ($env:KUBECTL_BIN) { $env:KUBECTL_BIN } else { "kubectl" })
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] $Message"
}

function Abort {
    param([string]$Message)
    Write-Error "ERROR: $Message"
    exit 1
}

function Check-Dep {
    param([string]$Bin)
    if (-not (Get-Command $Bin -ErrorAction SilentlyContinue)) {
        Abort "Required binary not found in PATH: $Bin"
    }
}

function Safe-Mkdir {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Sanitize-Filename {
    param([string]$Name)
    return ($Name -replace '[\/:@]', '_')
}

# ==== Init ====

Check-Dep -Bin $KubectlPath

if (-not $OutDir) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutDir = ".\k8s_audit_$stamp"
}

Safe-Mkdir -Path $OutDir
$SummaryMd = Join-Path $OutDir "SUMMARY.md"

Write-Log "Output directory: $OutDir"

if ($Namespace) {
    $KubectlNsArgs = @("-n", $Namespace)
    Write-Log "Namespace filter: $Namespace"
} else {
    $KubectlNsArgs = @("-A")
    Write-Log "Namespace filter: ALL"
}

# ==== 1. Cluster info ====

function Collect-ClusterInfo {
    Write-Log "Collecting cluster info..."
    $path = Join-Path $OutDir "cluster_info.txt"

    $lines = @()
    $lines += "# Cluster Info"
    $lines += ""
    $lines += "## kubectl version --short"
    try {
        $ver = & $KubectlPath version --short 2>&1
        $lines += $ver
    } catch {
        $lines += "kubectl version failed: $($_.Exception.Message)"
    }
    $lines += ""
    $lines += "## Current context"
    try {
        $ctx = & $KubectlPath config current-context 2>&1
        $lines += $ctx
    } catch {
        $lines += "current-context unknown: $($_.Exception.Message)"
    }
    $lines += ""
    $lines += "## Nodes"
    try {
        $nodes = & $KubectlPath get nodes -o wide 2>&1
        $lines += $nodes
    } catch {
        $lines += "kubectl get nodes failed: $($_.Exception.Message)"
    }

    $lines | Out-File -FilePath $path -Encoding UTF8 -Force
}

# ==== 2. Images ====

function Collect-Images {
    Write-Log "Collecting images from pods..."

    $imagesCsv = Join-Path $OutDir "images.csv"
    $latestCsv = Join-Path $OutDir "images_latest_or_tagless.csv"

    $allRows = @()

    try {
        $podsJson = & $KubectlPath get pods @KubectlNsArgs -o json 2>$null
        if (-not $podsJson) {
            Write-Log "No pods found or kubectl get pods failed (continuing)."
            return
        }
        $pods = $podsJson | ConvertFrom-Json
    } catch {
        Write-Log "kubectl get pods failed: $($_.Exception.Message)"
        return
    }

    if (-not $pods.items) {
        Write-Log "No pods for selected namespace scope."
        return
    }

    foreach ($pod in $pods.items) {
        $ns = $pod.metadata.namespace
        if (-not $ns) { $ns = "default" }
        $podName = $pod.metadata.name

        if (-not $pod.spec.containers) { continue }

        foreach ($c in $pod.spec.containers) {
            $image = $c.image
            $cName = $c.name

            $tag = ""
            if ($image -and $image.Contains(":")) {
                $tag = $image.Split(":")[-1]
            }
            if ([string]::IsNullOrEmpty($tag)) {
                $tagDisplay = "<none>"
            } else {
                $tagDisplay = $tag
            }

            $isLatestOrTagless = $false
            if ($image -and -not $image.Contains(":")) {
                $isLatestOrTagless = $true
            } elseif ($tag -eq "latest") {
                $isLatestOrTagless = $true
            }

            $allRows += [pscustomobject]@{
                namespace            = $ns
                pod                  = $podName
                container            = $cName
                image                = $image
                image_tag            = $tagDisplay
                is_latest_or_tagless = $isLatestOrTagless
            }
        }
    }

    if ($allRows.Count -eq 0) {
        Write-Log "No container images found."
        return
    }

    $allRows | Export-Csv -Path $imagesCsv -NoTypeInformation -Encoding UTF8

    $latestRows = @()
    foreach ($row in $allRows) {
        if (-not $row.is_latest_or_tagless) { continue }

        if (-not ($row.image -and $row.image.Contains(":"))) {
            $reason = "tagless_image"
        } else {
            $reason = "latest_tag"
        }

        $latestRows += [pscustomobject]@{
            namespace = $row.namespace
            pod       = $row.pod
            container = $row.container
            image     = $row.image
            image_tag = $row.image_tag
            reason    = $reason
        }
    }

    if ($latestRows.Count -gt 0) {
        $latestRows | Export-Csv -Path $latestCsv -NoTypeInformation -Encoding UTF8
    } else {
        "" | Out-File -FilePath $latestCsv -Encoding UTF8 -Force
    }
}

# ==== 3. NetworkPolicies ====

function Collect-NetworkPolicies {
    Write-Log "Collecting NetworkPolicy summary..."
    $csv = Join-Path $OutDir "networkpolicies_summary.csv"

    $rows = @()

    try {
        $json = & $KubectlPath get networkpolicy -A -o json 2>$null
        if (-not $json) {
            Write-Log "No NetworkPolicy resources found."
            "namespace,total_policies" | Out-File $csv -Encoding UTF8 -Force
            return
        }
        $np = $json | ConvertFrom-Json
    } catch {
        Write-Log "kubectl get networkpolicy failed: $($_.Exception.Message)"
        "namespace,total_policies" | Out-File $csv -Encoding UTF8 -Force
        return
    }

    if (-not $np.items) {
        Write-Log "No NetworkPolicy items."
        "namespace,total_policies" | Out-File $csv -Encoding UTF8 -Force
        return
    }

    $grouped = $np.items | Group-Object { $_.metadata.namespace }
    foreach ($g in $grouped) {
        $rows += [pscustomobject]@{
            namespace      = $g.Name
            total_policies = $g.Count
        }
    }

    $rows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
}

# ==== 4. PSA labels ====

function Collect-PsaLabels {
    Write-Log "Collecting Pod Security Admission labels..."
    $csv = Join-Path $OutDir "psa_namespace_labels.csv"

    $rows = @()

    try {
        $json = & $KubectlPath get ns -o json 2>$null
        if (-not $json) {
            Write-Log "kubectl get ns failed."
            "namespace,enforce,warn,audit" | Out-File $csv -Encoding UTF8 -Force
            return
        }
        $nss = $json | ConvertFrom-Json
    } catch {
        Write-Log "kubectl get ns failed: $($_.Exception.Message)"
        "namespace,enforce,warn,audit" | Out-File $csv -Encoding UTF8 -Force
        return
    }

    foreach ($ns in $nss.items) {
        $name   = $ns.metadata.name
        $labels = $ns.metadata.labels

        $enforce = ""
        $warn    = ""
        $audit   = ""

        if ($labels) {
            if ($labels.'pod-security.kubernetes.io/enforce') { $enforce = $labels.'pod-security.kubernetes.io/enforce' }
            if ($labels.'pod-security.kubernetes.io/warn')    { $warn    = $labels.'pod-security.kubernetes.io/warn' }
            if ($labels.'pod-security.kubernetes.io/audit')   { $audit   = $labels.'pod-security.kubernetes.io/audit' }
        }

        $rows += [pscustomobject]@{
            namespace = $name
            enforce   = $enforce
            warn      = $warn
            audit     = $audit
        }
    }

    $rows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
}

# ==== 5. RBAC ====

function Collect-RbacSummary {
    Write-Log "Collecting RBAC summary..."

    $crbCsv = Join-Path $OutDir "rbac_clusterrolebindings.csv"
    $crbRows = @()

    try {
        $json = & $KubectlPath get clusterrolebinding -o json 2>$null
        if ($json) {
            $crbs = $json | ConvertFrom-Json
            foreach ($b in $crbs.items) {
                $bname = $b.metadata.name
                $rkind = $b.roleRef.kind
                $rname = $b.roleRef.name
                $role  = "$rkind/$rname"

                if ($b.subjects) {
                    foreach ($s in $b.subjects) {
                        $crbRows += [pscustomobject]@{
                            binding           = $bname
                            role              = $role
                            subject_kind      = $s.kind
                            subject_name      = $s.name
                            subject_namespace = $s.namespace
                        }
                    }
                } else {
                    $crbRows += [pscustomobject]@{
                        binding           = $bname
                        role              = $role
                        subject_kind      = ""
                        subject_name      = ""
                        subject_namespace = ""
                    }
                }
            }
        } else {
            Write-Log "No ClusterRoleBinding resources found."
        }
    } catch {
        Write-Log "kubectl get clusterrolebinding failed: $($_.Exception.Message)"
    }

    if ($crbRows.Count -gt 0) {
        $crbRows | Export-Csv -Path $crbCsv -NoTypeInformation -Encoding UTF8
    } else {
        "binding,role,subject_kind,subject_name,subject_namespace" | Out-File $crbCsv -Encoding UTF8 -Force
    }

    $rbCsv = Join-Path $OutDir "rbac_rolebindings.csv"
    $rbRows = @()

    try {
        $json = & $KubectlPath get rolebinding @KubectlNsArgs -o json 2>$null
        if ($json) {
            $rbs = $json | ConvertFrom-Json
            foreach ($b in $rbs.items) {
                $ns    = $b.metadata.namespace
                if (-not $ns) { $ns = "default" }
                $bname = $b.metadata.name
                $rkind = $b.roleRef.kind
                $rname = $b.roleRef.name
                $role  = "$rkind/$rname"

                if ($b.subjects) {
                    foreach ($s in $b.subjects) {
                        $rbRows += [pscustomobject]@{
                            namespace         = $ns
                            binding           = $bname
                            role              = $role
                            subject_kind      = $s.kind
                            subject_name      = $s.name
                            subject_namespace = $s.namespace
                        }
                    }
                } else {
                    $rbRows += [pscustomobject]@{
                        namespace         = $ns
                        binding           = $bname
                        role              = $role
                        subject_kind      = ""
                        subject_name      = ""
                        subject_namespace = ""
                    }
                }
            }
        } else {
            Write-Log "No RoleBinding resources found."
        }
    } catch {
        Write-Log "kubectl get rolebinding failed: $($_.Exception.Message)"
    }

    if ($rbRows.Count -gt 0) {
        $rbRows | Export-Csv -Path $rbCsv -NoTypeInformation -Encoding UTF8
    } else {
        "namespace,binding,role,subject_kind,subject_name,subject_namespace" | Out-File $rbCsv -Encoding UTF8 -Force
    }
}

# ==== 6. Services / Ingress ====

function Collect-ServiceAndIngress {
    Write-Log "Collecting Service exposure summary..."

    $svcCsv = Join-Path $OutDir "services_exposure.csv"
    $svcRows = @()

    try {
        $json = & $KubectlPath get svc @KubectlNsArgs -o json 2>$null
        if ($json) {
            $svcs = $json | ConvertFrom-Json
            foreach ($s in $svcs.items) {
                $ns   = $s.metadata.namespace
                if (-not $ns) { $ns = "default" }
                $name = $s.metadata.name
                $type = $s.spec.type
                $cip  = $s.spec.clusterIP

                $extIPs = ""
                if ($s.spec.externalIPs) {
                    $extIPs = ($s.spec.externalIPs -join ";")
                }

                $lb = ""
                if ($s.status.loadBalancer -and $s.status.loadBalancer.ingress) {
                    $ingressStrings = @()
                    foreach ($ing in $s.status.loadBalancer.ingress) {
                        if ($ing.ip) { $ingressStrings += $ing.ip }
                        elseif ($ing.hostname) { $ingressStrings += $ing.hostname }
                    }
                    $lb = ($ingressStrings -join ";")
                }

                $ports = ""
                if ($s.spec.ports) {
                    $portStrings = @()
                    foreach ($p in $s.spec.ports) {
                        $proto = if ($p.protocol) { $p.protocol } else { "TCP" }
                        $portStrings += ("{0}/{1}" -f $p.port, $proto)
                    }
                    $ports = ($portStrings -join ";")
                }

                $svcRows += [pscustomobject]@{
                    namespace    = $ns
                    name         = $name
                    type         = $type
                    cluster_ip   = $cip
                    external_ips = $extIPs
                    loadbalancer = $lb
                    endpoints    = $ports
                }
            }
        } else {
            Write-Log "No Service resources found."
        }
    } catch {
        Write-Log "kubectl get svc failed: $($_.Exception.Message)"
    }

    if ($svcRows.Count -gt 0) {
        $svcRows | Export-Csv -Path $svcCsv -NoTypeInformation -Encoding UTF8
    } else {
        "namespace,name,type,cluster_ip,external_ips,loadbalancer,endpoints" | Out-File $svcCsv -Encoding UTF8 -Force
    }

    Write-Log "Collecting Ingress exposure summary..."

    $ingCsv = Join-Path $OutDir "ingress_exposure.csv"
    $ingRows = @()

    try {
        $json = & $KubectlPath get ingress @KubectlNsArgs -o json 2>$null
        if ($json) {
            $ings = $json | ConvertFrom-Json
            foreach ($ing in $ings.items) {
                $ns   = $ing.metadata.namespace
                if (-not $ns) { $ns = "default" }
                $name = $ing.metadata.name
                $cls  = $ing.spec.ingressClassName

                $hosts = @()
                if ($ing.spec.rules) {
                    foreach ($rule in $ing.spec.rules) {
                        if ($rule.host) {
                            $hosts += $rule.host
                        }
                    }
                    $hosts = $hosts | Sort-Object -Unique
                }
                $hostsStr = ($hosts -join ";")

                $tlsEnabled = "false"
                if ($ing.spec.tls -and $ing.spec.tls.Count -gt 0) {
                    $tlsEnabled = "true"
                }

                $ingRows += [pscustomobject]@{
                    namespace     = $ns
                    name          = $name
                    ingress_class = $cls
                    hosts         = $hostsStr
                    tls_enabled   = $tlsEnabled
                }
            }
        } else {
            Write-Log "No Ingress resources found."
        }
    } catch {
        Write-Log "kubectl get ingress failed: $($_.Exception.Message)"
    }

    if ($ingRows.Count -gt 0) {
        $ingRows | Export-Csv -Path $ingCsv -NoTypeInformation -Encoding UTF8
    } else {
        "namespace,name,ingress_class,hosts,tls_enabled" | Out-File $ingCsv -Encoding UTF8 -Force
    }
}

# ==== 7. Trivy scans (optional) ====

function Run-TrivyScans {
    if ($TrivyScanLimit -le 0) {
        Write-Log "Trivy scan not requested (skip)."
        return
    }

    if (-not (Get-Command "trivy" -ErrorAction SilentlyContinue)) {
        Write-Log "Trivy not found in PATH; skipping image scans."
        return
    }

    $imagesCsv = Join-Path $OutDir "images.csv"
    if (-not (Test-Path $imagesCsv)) {
        Write-Log "images.csv not found; skipping Trivy scans."
        return
    }

    $imgList = (Import-Csv $imagesCsv).image |
        Where-Object { $_ -and $_.Trim() -ne "" } |
        Sort-Object -Unique

    if (-not $imgList) {
        Write-Log "No images to scan."
        return
    }

    Write-Log "Running Trivy scans for up to $TrivyScanLimit images..."

    $count = 0
    foreach ($img in $imgList) {
        $count++
        if ($count -gt $TrivyScanLimit) { break }

        $san = Sanitize-Filename -Name $img
        $outReport = Join-Path $OutDir ("trivy_{0}_{1}.txt" -f $count, $san)

        Write-Log ("  [{0}/{1}] trivy image scan: {2}" -f $count, $TrivyScanLimit, $img)
        try {
            trivy image --severity CRITICAL,HIGH --ignore-unfixed --no-progress $img |
                Out-File -FilePath $outReport -Encoding UTF8 -Force
        } catch {
            Write-Log "  Trivy scan failed for $img (see $outReport)"
            $_ | Out-File -FilePath $outReport -Encoding UTF8 -Append
        }
    }
}

# ==== 8. Summary ====

function Write-Summary {
    Write-Log "Writing summary markdown..."

    # File list to show in summary
    $files = @(
        "cluster_info.txt",
        "images.csv",
        "images_latest_or_tagless.csv",
        "networkpolicies_summary.csv",
        "psa_namespace_labels.csv",
        "rbac_clusterrolebindings.csv",
        "rbac_rolebindings.csv",
        "services_exposure.csv",
        "ingress_exposure.csv"
    )

    # Namespace display string (no parentheses in expression)
    if ([string]::IsNullOrEmpty($Namespace)) {
        $nsDisplay = "ALL"
    } else {
        $nsDisplay = $Namespace
    }

    # Build markdown lines
    $lines = @()
    $lines += "# Kubernetes Security Audit Summary"
    $lines += ""

    $generatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $lines += "- Generated at: $generatedAt"
    $lines += "- Namespace filter: $nsDisplay"
    $lines += ""
    $lines += "## Files"
    $lines += ""

    foreach ($f in $files) {
        $full = Join-Path $OutDir $f
        if (Test-Path $full) {
            # backtick in string: use double quotes and escape with backtick
            $lines += "- `$f`"
        }
    }

    # Trivy report files (no pipeline)
    $trivyReports = @()

    if (Test-Path $OutDir) {
        $allFiles = Get-ChildItem -Path $OutDir -ErrorAction SilentlyContinue
        foreach ($file in $allFiles) {
            if ($file.Name -like 'trivy_*.txt') {
                $trivyReports += $file
            }
        }
    }

    if ($trivyReports.Count -gt 0) {
        $lines += ""
        $lines += "## Trivy Reports"
        foreach ($r in $trivyReports) {
            $lines += "- `$($r.Name)`"
        }
    }

    $lines += ""
    $lines += "## Notes"
    $lines += ""
    $lines += "- This script is read-only: it does not modify any Kubernetes resources."
    $lines += "- RBAC summaries show who is bound to which roles (ClusterRoleBinding / RoleBinding)."
    $lines += "- Service / Ingress summaries help identify external exposure (LoadBalancer, NodePort, public hosts, TLS usage)."
    $lines += "- All checks are best-effort and may not cover every security requirement."
    $lines += "- You can extend this script with more checks (CIS-style policies, privileged pods, hostPath, etc.)."

    $lines | Out-File -FilePath $SummaryMd -Encoding UTF8 -Force
}

# ==== Main ====

Collect-ClusterInfo
Collect-Images
Collect-NetworkPolicies
Collect-PsaLabels
Collect-RbacSummary
Collect-ServiceAndIngress
Run-TrivyScans
Write-Summary

Write-Log "Done. See $OutDir for results."