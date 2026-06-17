<?php
// =============================================================
// DOMAIN INTELLIGENCE CHECKER — Professional Edition v2.0
// =============================================================
session_start();

// ---- CSRF Protection ----
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// ---- Rate Limiting ----
function checkRateLimit($maxRequests = 15, $windowSeconds = 60) {
    $now = time();
    if (!isset($_SESSION['rate_limit'])) {
        $_SESSION['rate_limit'] = [];
    }
    $_SESSION['rate_limit'] = array_filter($_SESSION['rate_limit'], function($t) use ($now, $windowSeconds) {
        return ($now - $t) < $windowSeconds;
    });
    if (count($_SESSION['rate_limit']) >= $maxRequests) {
        return false;
    }
    $_SESSION['rate_limit'][] = $now;
    return true;
}

// ---- HTTP helper ----
function httpGet($url, $timeout = 6)
{
    if (!function_exists('curl_init')) return null;
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT      => 'DomainIntelligenceChecker/2.0',
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
        CURLOPT_ENCODING       => '',
    ]);
    $res = curl_exec($ch);
    return $res ?: null;
}

// ---- DNS lookup ----
function getDNSRecords($domain)
{
    $records = [];
    $allRecords = [];

    $native = @dns_get_record($domain, DNS_ALL);
    if ($native) {
        $allRecords = array_merge($allRecords, $native);
    }

    $safeDomain = escapeshellarg($domain);
    if (function_exists('shell_exec')) {
        $output = @shell_exec("dig +short +time=2 +tries=1 {$safeDomain} A 2>/dev/null");
        if ($output) {
            foreach (array_filter(explode("\n", trim($output))) as $ip) {
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $allRecords[] = ['type' => 'A', 'ip' => $ip, 'ttl' => 300];
                }
            }
        }

        $output = @shell_exec("dig +short +time=2 +tries=1 {$safeDomain} AAAA 2>/dev/null");
        if ($output) {
            foreach (array_filter(explode("\n", trim($output))) as $ip) {
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $allRecords[] = ['type' => 'AAAA', 'ipv6' => $ip, 'ttl' => 300];
                }
            }
        }
    }

    $seen = [];
    foreach ($allRecords as $r) {
        $type = $r['type'] ?? '';
        if ($type === 'A' && !empty($r['ip'])) {
            $key = 'A_' . $r['ip'];
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $records['A'][] = ['ip' => $r['ip'], 'ttl' => $r['ttl'] ?? 300];
            }
        } elseif ($type === 'AAAA' && !empty($r['ipv6'])) {
            $key = 'AAAA_' . $r['ipv6'];
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $records['AAAA'][] = ['ip' => $r['ipv6'], 'ttl' => $r['ttl'] ?? 300];
            }
        } elseif ($type === 'MX' && !empty($r['target'])) {
            $key = 'MX_' . $r['target'];
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $records['MX'][] = ['pri' => $r['pri'] ?? 10, 'target' => $r['target'], 'ttl' => $r['ttl'] ?? 300];
            }
        } elseif ($type === 'NS' && !empty($r['target'])) {
            $key = 'NS_' . $r['target'];
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $records['NS'][] = ['target' => $r['target'], 'ttl' => $r['ttl'] ?? 300];
            }
        } elseif ($type === 'TXT' && !empty($r['txt'])) {
            $key = 'TXT_' . md5($r['txt']);
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $records['TXT'][] = ['txt' => $r['txt'], 'ttl' => $r['ttl'] ?? 300];
            }
        } elseif ($type === 'CNAME' && !empty($r['target'])) {
            $records['CNAME'] = ['target' => $r['target'], 'ttl' => $r['ttl'] ?? 300];
        } elseif ($type === 'SOA') {
            $records['SOA'] = $r;
        }
    }

    if (!empty($records['MX'])) {
        usort($records['MX'], fn($a, $b) => $a['pri'] - $b['pri']);
    }

    return $records;
}

// ---- Subdomain enumeration ----
function getSubdomains($domain)
{
    $subdomains = [];
    
    $common = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
        'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
        'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
        'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
        'web', 'media', 'email', 'images', 'img', 'download', 'dns', 'piwik', 'stats',
        'dashboard', 'portal', 'manage', 'start', 'info', 'apps', 'app', 'api',
        'cdn', 'files', 'upload', 'backup', 'db', 'remote', 'ssh', 'git', 'svn',
        'jenkins', 'jira', 'confluence', 'gitlab', 'monitor', 'status', 'uptime',
        'chat', 'irc', 'xmpp', 'proxy', 'cache', 'static', 'assets', 'res',
        'stage', 'staging', 'test', 'testing', 'qa', 'uat', 'dev', 'development',
        'staging', 'sandbox', 'playground', 'demo', 'preprod', 'prod', 'production',
        'internal', 'external', 'public', 'private', 'corp', 'corporate', 'company',
        'portal', 'gateway', 'hub', 'dashboard', 'admin', 'manager', 'control',
        'ns1', 'ns2', 'ns3', 'ns4', 'dns1', 'dns2', 'dns3',
        'mx', 'mx1', 'mx2', 'mx3', 'mailserver', 'exchange',
        'ftp', 'sftp', 'ftps', 'file', 'files',
        'vpn', 'vpn1', 'vpn2', 'openvpn', 'pptp', 'l2tp',
        'blog', 'blogs', 'wordpress', 'wp', 'cms',
        'shop', 'store', 'checkout', 'cart', 'payment', 'payments',
        'api', 'rest', 'soap', 'graphql', 'swagger', 'docs', 'documentation',
        'cdn', 'media', 'static', 'assets', 'img', 'images', 'video', 'videos',
        'download', 'downloads', 'upload', 'uploads', 'share', 'shares',
        'monitor', 'monitoring', 'status', 'uptime', 'health', 'alerts',
        'chat', 'irc', 'xmpp', 'slack', 'discord', 'mattermost',
        'git', 'gitlab', 'github', 'bitbucket', 'svn', 'jenkins', 'jira', 'confluence',
        'analytics', 'stats', 'metrics', 'logs', 'logging',
        'backup', 'backups', 'restore', 'recovery',
        'cache', 'caching', 'proxy', 'proxies', 'loadbalancer', 'lb',
        'web', 'webserver', 'http', 'https', 'ssl', 'tls',
        'db', 'database', 'mysql', 'postgres', 'postgresql', 'mongodb', 'redis',
        'elastic', 'elasticsearch', 'kibana', 'grafana', 'prometheus',
        'kafka', 'rabbitmq', 'mqtt', 'amqp',
        'docker', 'k8s', 'kubernetes', 'openshift', 'swarm',
        'cloud', 'aws', 'azure', 'gcp', 'google', 'amazon',
        'security', 'firewall', 'ids', 'ips', 'waf',
        'ad', 'ldap', 'kerberos', 'radius', 'ntp', 'sip', 'voip',
        'asterisk', 'pbx', 'freepbx', 'elastix',
        'odoo', 'erp', 'crm', 'sales', 'marketing', 'analytics',
        'research', 'lab', 'science', 'tech', 'innovation',
        'learn', 'training', 'courses', 'academy', 'university'
    ];

    foreach ($common as $sub) {
        $full = $sub . '.' . $domain;
        $ip = @gethostbyname($full);
        if ($ip && $ip !== $full) {
            $subdomains[$full] = [
                'source' => 'DNS Brute',
                'ip' => $ip,
                'resolved' => true
            ];
        }
    }

    $count = 0;
    foreach ($subdomains as $host => &$info) {
        if ($count >= 10) break;
        if (!empty($info['ip'])) {
            $asnInfo = getASNInfoFast($info['ip']);
            if ($asnInfo) {
                $info['asn'] = $asnInfo['asn'] ?? null;
                $info['asn_name'] = $asnInfo['name'] ?? null;
            }
            $count++;
        }
    }

    ksort($subdomains);
    return $subdomains;
}

// ---- ASN/ISP lookup ----
function getASNInfoFast($ip)
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return null;
    
    $response = httpGet("https://ipinfo.io/{$ip}/json", 3);
    if (!$response) return null;
    $data = json_decode($response, true);
    if (!$data) return null;
    $info = [];
    if (!empty($data['org'])) {
        if (preg_match('/^AS(\d+)\s+(.+)$/', $data['org'], $matches)) {
            $info['asn'] = 'AS' . $matches[1];
            $info['name'] = $matches[2];
        } else {
            $info['name'] = $data['org'];
        }
    }
    return $info ?: null;
}

// ---- Extract Registrar URL ----
function extractRegistrarUrl($raw, $registrar)
{
    $url = null;
    
    if (!empty($raw)) {
        $patterns = [
            '/Registrar URL:\s*(.+)/i',
            '/Registrar URL\s*:\s*(.+)/i',
            '/URL of the Registrar:\s*(.+)/i',
            '/Registrar Website:\s*(.+)/i',
            '/Registrar Homepage:\s*(.+)/i',
            '/http[s]?:\/\/[^\s]+/i',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $raw, $matches)) {
                $found = trim($matches[1]);
                if (filter_var($found, FILTER_VALIDATE_URL) || strpos($found, 'http') === 0) {
                    $url = $found;
                    break;
                }
                if (strpos($found, '.') !== false && strpos($found, ' ') === false) {
                    $url = 'https://' . $found;
                    break;
                }
            }
        }
        
        if (!$url) {
            preg_match_all('/https?:\/\/[^\s\n\r]+/i', $raw, $links);
            if (!empty($links[0])) {
                $registrarKeywords = ['registrar', 'whois', 'domain', 'register', 'nic', 'registry'];
                foreach ($links[0] as $link) {
                    $linkLower = strtolower($link);
                    foreach ($registrarKeywords as $keyword) {
                        if (strpos($linkLower, $keyword) !== false) {
                            $url = $link;
                            break 2;
                        }
                    }
                }
                if (!$url) {
                    $url = $links[0][0];
                }
            }
        }
    }
    
    if (!$url && $registrar) {
        $map = [
            'godaddy'=>'https://www.godaddy.com',
            'namecheap'=>'https://www.namecheap.com',
            'google'=>'https://domains.google',
            'cloudflare'=>'https://www.cloudflare.com/registrar/',
            'enom'=>'https://www.enom.com',
            'network solutions'=>'https://www.networksolutions.com',
            'ionos'=>'https://www.ionos.com',
            'name.com'=>'https://www.name.com',
            'hover'=>'https://www.hover.com',
            'gandi'=>'https://www.gandi.net',
            'ovh'=>'https://www.ovh.com',
            'markmonitor'=>'https://www.markmonitor.com',
            'dynadot'=>'https://www.dynadot.com',
            'porkbun'=>'https://porkbun.com',
            'bluehost'=>'https://www.bluehost.com',
            'hostgator'=>'https://www.hostgator.com',
            'dreamhost'=>'https://www.dreamhost.com',
            'register.com'=>'https://www.register.com',
            'eurodns'=>'https://www.eurodns.com',
            'csc'=>'https://www.cscglobal.com',
            'safenames'=>'https://www.safenames.net',
            'key-systems'=>'https://www.key-systems.net',
            'internet.bs'=>'https://internetbs.net',
        ];
        $lower = strtolower($registrar);
        foreach ($map as $key => $mapUrl) {
            if (strpos($lower, $key) !== false) return $mapUrl;
        }
    }
    
    return $url;
}

// ---- Input cleaning ----
function cleanDomain($d)
{
    $d = strtolower(trim($d));
    $d = preg_replace('#^https?://#', '', $d);
    $d = preg_replace('#^www\.#', '', $d);
    $d = strtok($d, '/?#');
    $d = rtrim($d, '.');
    return substr($d, 0, 253);
}

function isValidDomain($d)
{
    return (bool) preg_match('/^(?!-)(?:[a-z0-9\-]{1,63}\.)+[a-z]{2,}$/i', $d);
}

function getTLD($domain)
{
    $p = explode('.', $domain);
    return count($p) >= 2 ? end($p) : '';
}

// ---- Time helpers ----
function timeDiff($date, $future = true)
{
    if (!$date) return null;
    $timestamp = strtotime($date);
    if (!$timestamp) return null;
    $diff = $future ? ($timestamp - time()) : (time() - $timestamp);
    if ($diff < 0 && $future) return 'Expired';
    $years = floor($diff / (365.25 * 86400));
    $months = floor(fmod($diff, 365.25 * 86400) / (30.44 * 86400));
    $days = floor(fmod($diff, 30.44 * 86400) / 86400);
    $parts = [];
    if ($years > 0) $parts[] = $years . 'y';
    if ($months > 0) $parts[] = $months . 'mo';
    if ($days > 0 || empty($parts)) $parts[] = $days . 'd';
    return implode(' ', $parts);
}

function getDomainAge($created) { return $created ? timeDiff($created, false) : null; }

function isDomainAvailable($data)
{
    if (!$data) return true;
    if (!empty($data['status'])) {
        foreach ($data['status'] as $s) {
            if (strpos($s, 'available') !== false) return true;
        }
    }
    if (!empty($data['raw']) && preg_match('/No match for|NOT FOUND|is available|No entries found|No data found|Status: free/i', $data['raw'])) {
        return true;
    }
    if (empty($data['expiry']) && empty($data['created']) && empty($data['registrar'])) return true;
    return false;
}

// =============================================================
// RDAP
// =============================================================
function lookupRDAP($domain)
{
    $urls = [
        "https://rdap.org/domain/" . urlencode($domain),
        "https://rdap.iana.org/domain/" . urlencode($domain),
    ];
    foreach ($urls as $url) {
        $json = httpGet($url);
        if (!$json) continue;
        $data = json_decode($json, true);
        if (!$data || !empty($data['errorCode'])) continue;
        $r = makeEmptyResult('RDAP', $domain);
        $r = parseRDAPData($data, $r);
        if ($r['expiry'] || $r['created']) return $r;
    }
    return null;
}

function makeEmptyResult($source, $domain) {
    return [
        'source' => $source, 'domain' => $domain,
        'created' => null, 'updated' => null, 'expiry' => null,
        'status' => [], 'nameservers' => [],
        'registrar' => null, 'registrar_url' => null,
        'registrant' => null,
        'registrant_org' => null, 'registrant_email' => null,
        'registrant_country' => null, 'registrant_address' => null,
        'registrant_phone' => null,
        'admin' => null, 'admin_email' => null,
        'tech' => null, 'tech_email' => null,
        'billing' => null, 'dnssec' => null, 'raw' => null, 'rdap_link' => null,
    ];
}

function parseRDAPData($data, $r) {
    foreach ($data['events'] ?? [] as $e) {
        switch ($e['eventAction'] ?? '') {
            case 'registration': $r['created'] = $e['eventDate']; break;
            case 'expiration':   $r['expiry']  = $e['eventDate']; break;
            case 'last changed': $r['updated'] = $e['eventDate']; break;
        }
    }
    $r['status'] = array_map('strtolower', $data['status'] ?? []);
    foreach ($data['nameservers'] ?? [] as $ns) {
        if (!empty($ns['ldhName'])) $r['nameservers'][] = strtolower($ns['ldhName']);
    }
    if (isset($data['secureDNS'])) {
        $r['dnssec'] = !empty($data['secureDNS']['delegationSigned']) ? 'Signed' : 'Unsigned';
    }
    return extractRDAPEntities($data['entities'] ?? [], $r);
}

function extractRDAPEntities($entities, $r)
{
    foreach ($entities as $ent) {
        $roles = array_map('strtolower', $ent['roles'] ?? []);
        $name = $org = $email = $phone = $country = $addr = null;
        $url = null;
        
        foreach ($ent['vcardArray'][1] ?? [] as $v) {
            switch ($v[0] ?? '') {
                case 'fn':  $name  = $v[3] ?? null; break;
                case 'org': $org   = is_array($v[3]) ? implode(', ', $v[3]) : ($v[3] ?? null); break;
                case 'email': $email = $v[3] ?? null; break;
                case 'tel': $phone = $v[3] ?? null; break;
                case 'url': $url = $v[3] ?? null; break;
                case 'adr':
                    $a = $v[3] ?? [];
                    if (is_array($a)) {
                        $country = $a[6] ?? null;
                        $parts = array_filter([$a[2]??null,$a[3]??null,$a[4]??null,$a[5]??null]);
                        if ($parts) $addr = implode(', ', $parts);
                    }
                    break;
            }
        }
        if (!$name && !empty($ent['handle'])) $name = $ent['handle'];
        if (in_array('registrar', $roles)) {
            $r['registrar'] = $name ?? $org ?? $r['registrar'];
            if ($url) $r['registrar_url'] = $url;
        }
        if (in_array('registrant', $roles)) {
            $r['registrant']         = $name ?? $r['registrant'];
            $r['registrant_org']     = $org ?? $r['registrant_org'];
            $r['registrant_email']   = $email ?? $r['registrant_email'];
            $r['registrant_phone']   = $phone ?? $r['registrant_phone'];
            $r['registrant_country'] = $country ?? $r['registrant_country'];
            $r['registrant_address'] = $addr ?? $r['registrant_address'];
        }
        if (in_array('administrative', $roles)) {
            $r['admin'] = $name ?? $r['admin'];
            $r['admin_email'] = $email ?? $r['admin_email'];
        }
        if (in_array('technical', $roles)) {
            $r['tech'] = $name ?? $r['tech'];
            $r['tech_email'] = $email ?? $r['tech_email'];
        }
        if (in_array('billing', $roles)) $r['billing'] = $name ?? $org ?? $r['billing'];
        if (!empty($ent['entities'])) $r = extractRDAPEntities($ent['entities'], $r);
    }
    return $r;
}

// =============================================================
// IANA RDAP Bootstrap
// =============================================================
function getBootstrapRDAPUrl($domain)
{
    $tld = getTLD($domain);
    $boot = httpGet("https://data.iana.org/rdap/dns.json", 6);
    if (!$boot) return null;
    $data = json_decode($boot, true);
    foreach ($data['services'] ?? [] as $svc) {
        $tlds = array_map('strtolower', $svc[0] ?? []);
        if (in_array($tld, $tlds)) {
            $servers = $svc[1] ?? [];
            if ($servers) return rtrim($servers[0], '/') . '/domain/' . urlencode($domain);
        }
    }
    return null;
}

function lookupRDAPBootstrap($domain)
{
    $url = getBootstrapRDAPUrl($domain);
    if (!$url) return null;
    $json = httpGet($url);
    if (!$json) return null;
    $data = json_decode($json, true);
    if (!$data || !empty($data['errorCode'])) return null;
    $r = makeEmptyResult('RDAP (Registry)', $domain);
    $r = parseRDAPData($data, $r);
    return ($r['expiry'] || $r['created']) ? $r : null;
}

// =============================================================
// WHOIS
// =============================================================
function getWhoisServer($domain)
{
    $parts = explode('.', $domain);
    $tld   = strtolower(end($parts));
    $sld   = count($parts) >= 3 ? strtolower($parts[count($parts)-2] . '.' . $tld) : null;

    $map = [
        'ug'=>'whois.co.ug','co.ug'=>'whois.co.ug',
        'ke'=>'whois.kenic.or.ke','co.ke'=>'whois.kenic.or.ke',
        'tz'=>'whois.tznic.or.tz','co.tz'=>'whois.tznic.or.tz',
        'com'=>'whois.verisign-grs.com','net'=>'whois.verisign-grs.com',
        'org'=>'whois.pir.org','info'=>'whois.afilias.net','biz'=>'whois.biz',
        'uk'=>'whois.nic.uk','co.uk'=>'whois.nic.uk',
        'de'=>'whois.denic.de','fr'=>'whois.afnic.fr',
        'nl'=>'whois.domain-registry.nl','eu'=>'whois.eu',
        'es'=>'whois.nic.es','it'=>'whois.nic.it',
        'jp'=>'whois.jprs.jp','cn'=>'whois.cnnic.cn',
        'in'=>'whois.registry.in',
        'au'=>'whois.auda.org.au','com.au'=>'whois.auda.org.au',
        'nz'=>'whois.irs.net.nz','co.nz'=>'whois.irs.net.nz',
        'us'=>'whois.nic.us','ca'=>'whois.cira.ca',
        'br'=>'whois.registro.br','com.br'=>'whois.registro.br',
        'ai'=>'whois.nic.ai','io'=>'whois.nic.io','co'=>'whois.nic.co',
        'me'=>'whois.nic.me','tv'=>'whois.nic.tv','cc'=>'whois.nic.cc',
        'ws'=>'whois.website.ws','xyz'=>'whois.nic.xyz',
        'tech'=>'whois.nic.tech','online'=>'whois.nic.online','site'=>'whois.nic.site',
        'app'=>'whois.nic.google','dev'=>'whois.nic.google','page'=>'whois.nic.google',
        'za'=>'whois.registry.net.za','co.za'=>'whois.registry.net.za',
        'ng'=>'whois.nira.net.ng','com.ng'=>'whois.nira.net.ng',
        'edu'=>'whois.educause.edu','gov'=>'whois.nic.gov',
    ];

    if ($sld && isset($map[$sld])) return $map[$sld];
    if (isset($map[$tld])) return $map[$tld];
    return getIANAWhoisServer($tld);
}

function getIANAWhoisServer($tld)
{
    $raw = httpGet("https://www.iana.org/domains/root/db/{$tld}.html", 4);
    if ($raw && preg_match('/WHOIS Server:\s*([a-z0-9.\-]+)/i', $raw, $m)) {
        return trim($m[1]);
    }
    return 'whois.iana.org';
}

function lookupWHOIS($domain)
{
    $server = getWhoisServer($domain);
    if (!$server) return null;

    $prefix = '';
    if (strpos($server, 'denic.de') !== false) $prefix = '-T dn,ace ';
    if (strpos($server, 'dk-hostmaster') !== false) $prefix = '--show-handles ';
    if (strpos($server, 'afnic.fr') !== false) $prefix = '-V md2 ';

    $fp = @fsockopen($server, 43, $errno, $errstr, 6);
    if (!$fp) return null;
    fwrite($fp, $prefix . $domain . "\r\n");
    $raw = '';
    while (!feof($fp)) $raw .= fgets($fp, 4096);
    fclose($fp);
    if (empty(trim($raw))) return null;

    $r = makeEmptyResult('WHOIS', $domain);
    $r['raw'] = $raw;

    $patterns = [
        'created'  => '/(?:Creation Date|Created On|created|Registration Date|Registered on):\s*(.+)/i',
        'updated'  => '/(?:Updated Date|Last Updated|Last Modified|changed):\s*(.+)/i',
        'expiry'   => '/(?:Registry Expiry Date|Expir(?:y|ation) Date|Expiry|paid-till|Expires On):\s*(.+)/i',
        'registrar'=> '/(?:Registrar|Sponsoring Registrar|Registrar Name):\s*(.+)/i',
        'registrar_url'=> '/(?:Registrar URL|URL of the Registrar|Registrar Website|Registrar Homepage):\s*(.+)/i',
        'registrant'=> '/Registrant(?: Name)?:\s*(.+)/i',
        'registrant_org'    => '/Registrant Organ?i[sz]ation:\s*(.+)/i',
        'registrant_email'  => '/Registrant Email:\s*(.+)/i',
        'registrant_phone'  => '/Registrant Phone:\s*(.+)/i',
        'registrant_country'=> '/Registrant Country:\s*(.+)/i',
        'registrant_address'=> '/Registrant (?:Street|Address):\s*(.+)/i',
        'admin'     => '/Admin(?:istrative)?(?: Name)?:\s*(.+)/i',
        'admin_email'=> '/Admin Email:\s*(.+)/i',
        'tech'      => '/Tech(?:nical)?(?: Name)?:\s*(.+)/i',
        'tech_email'=> '/Tech Email:\s*(.+)/i',
        'dnssec'    => '/DNSSEC:\s*(.+)/i',
    ];
    foreach ($patterns as $key => $pat) {
        if (preg_match($pat, $raw, $m)) {
            $r[$key] = trim(strip_tags($m[1]));
        }
    }

    if (empty($r['registrar_url'])) {
        $r['registrar_url'] = extractRegistrarUrl($raw, $r['registrar']);
    }

    if (preg_match_all('/Domain Status:\s*(.+)/i', $raw, $m)) {
        foreach ($m[1] as $s) {
            $s = strtolower(trim(explode(' ', trim($s))[0]));
            if ($s) $r['status'][] = $s;
        }
    }
    if (preg_match_all('/(?:Name Server|nserver|Nameserver):\s*(.+)/i', $raw, $m)) {
        foreach ($m[1] as $ns) {
            $ns = strtolower(trim(preg_replace('/\s+.*$/', '', $ns)));
            if ($ns && !in_array($ns, $r['nameservers'])) $r['nameservers'][] = $ns;
        }
    }
    if (preg_match('/No match for|NOT FOUND|is available|No entries found/i', $raw)) {
        $r['status'][] = 'available';
    }
    return $r;
}

// =============================================================
// Display helpers
// =============================================================
function daysLeft($expiry)
{
    $t = strtotime($expiry);
    return $t ? (int) floor(($t - time()) / 86400) : null;
}

function fmtDate($d)
{
    if (!$d) return '<span class="na">Unknown</span>';
    $d = trim($d);
    $d = preg_replace('/\.\d{1,6}Z$/', 'Z', $d);
    try {
        $dt = new DateTime($d);
        return $dt->format('d M Y · H:i') . ' <span class="tz">UTC</span>';
    } catch (Exception $e) {}
    $t = strtotime($d);
    if ($t !== false) return date('d M Y · H:i', $t) . ' <span class="tz">UTC</span>';
    return '<span class="na">' . htmlspecialchars($d) . '</span>';
}

function statusBadge($s)
{
    $s = strtolower(trim(explode(' ', $s)[0]));
    $c = 'badge-default';
    if ($s === 'ok' || $s === 'active') $c = 'badge-ok';
    elseif (strpos($s,'lock') !== false || strpos($s,'hold') !== false) $c = 'badge-warn';
    elseif (strpos($s,'delete') !== false || strpos($s,'expir') !== false || strpos($s,'suspend') !== false) $c = 'badge-danger';
    elseif ($s === 'available') $c = 'badge-ok';
    return "<span class='badge {$c}'>" . htmlspecialchars($s) . "</span>";
}

function colorClass($days)
{
    if ($days === null) return 'muted';
    if ($days < 0)     return 'danger';
    if ($days <= 30)   return 'danger';
    if ($days <= 90)   return 'warn';
    return 'ok';
}

// =============================================================
// MAIN
// =============================================================
$result = null;
$error  = null;
$domain = '';
$dnsRecords = null;
$subdomains = [];
$isAvailable = false;
$registrarUrl = null;
$csrfToken = generateCSRFToken();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Invalid session. Please reload the page and try again.";
    } elseif (!checkRateLimit()) {
        $error = "Too many requests. Please wait a moment and try again.";
    } else {
        $domain = cleanDomain($_POST['domain'] ?? '');
        if (!isValidDomain($domain)) {
            $error = "Please enter a valid domain name (e.g. example.com)";
        } else {
            $data = lookupRDAP($domain);
            if (!$data || (!$data['expiry'] && !$data['created'])) {
                $data = lookupRDAPBootstrap($domain);
            }
            if (!$data || (!$data['expiry'] && !$data['created'])) {
                $data = lookupWHOIS($domain);
            }

            $isAvailable = isDomainAvailable($data);
            if ($data && !$isAvailable) {
                $result = $data;
                if (!empty($result['expiry'])) {
                    $result['days'] = daysLeft($result['expiry']);
                    $result['time_left'] = timeDiff($result['expiry'], true);
                }
                if (!empty($result['created'])) {
                    $result['age'] = getDomainAge($result['created']);
                }
                if (empty($result['registrar_url']) && !empty($result['raw'])) {
                    $result['registrar_url'] = extractRegistrarUrl($result['raw'], $result['registrar'] ?? '');
                }
                $registrarUrl = $result['registrar_url'] ?? null;
                
                if (empty($result['raw']) && $data) {
                    $whoisData = lookupWHOIS($domain);
                    if ($whoisData && !empty($whoisData['raw'])) {
                        $result['raw'] = $whoisData['raw'];
                        if (empty($result['registrar_url'])) {
                            $result['registrar_url'] = extractRegistrarUrl($result['raw'], $result['registrar'] ?? '');
                            $registrarUrl = $result['registrar_url'];
                        }
                    }
                }
            } elseif (!$isAvailable && !$data) {
                $error = "Could not retrieve data for <strong>" . htmlspecialchars($domain) . "</strong>.";
            }
            
            if ($result && !$isAvailable) {
                $dnsRecords = getDNSRecords($domain);
                $subdomains = getSubdomains($domain);
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= $domain ? htmlspecialchars($domain) . ' — Domain Intelligence' : 'Domain Intelligence Checker' ?></title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
/* ============================================================
   CLEAN DESIGN — Inspired by iLovePDF
   ============================================================ */

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    background: #f7f9fc;
    color: #1a1a2e;
    line-height: 1.6;
    padding: 0;
    min-height: 100vh;
}

/* ─── Container ─── */
.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 32px 20px 60px;
}

/* ─── Header ─── */
.header {
    text-align: center;
    padding: 40px 24px 36px;
    margin-bottom: 32px;
    background: #ffffff;
    border-radius: 16px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    border: 1px solid #eaeef2;
}

.header .logo {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #6b7a8f;
    margin-bottom: 12px;
}

.header .logo span {
    color: #2563eb;
}

.header h1 {
    font-size: 34px;
    font-weight: 800;
    letter-spacing: -0.02em;
    margin-bottom: 6px;
    color: #1a1a2e;
}

.header h1 span {
    color: #2563eb;
}

.header .sub {
    color: #6b7a8f;
    font-size: 15px;
    font-weight: 400;
}

/* ─── Search ─── */
.search-wrap {
    max-width: 680px;
    margin: 0 auto 28px;
}

.search-form {
    display: flex;
    gap: 10px;
    background: #ffffff;
    padding: 6px;
    border: 2px solid #dce1e8;
    border-radius: 12px;
    transition: border-color 0.2s, box-shadow 0.2s;
    box-shadow: 0 1px 3px rgba(0,0,0,0.03);
}

.search-form:focus-within {
    border-color: #2563eb;
    box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.08);
}

.search-form input {
    flex: 1;
    padding: 14px 18px;
    background: transparent;
    border: none;
    outline: none;
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    font-weight: 500;
    color: #1a1a2e;
}

.search-form input::placeholder {
    color: #9aa9b9;
    font-weight: 400;
}

.search-form button {
    padding: 14px 32px;
    background: #2563eb;
    color: #ffffff;
    border: none;
    border-radius: 10px;
    font-family: 'Inter', sans-serif;
    font-weight: 700;
    font-size: 14px;
    cursor: pointer;
    transition: background 0.15s, transform 0.1s;
    white-space: nowrap;
}

.search-form button:hover {
    background: #1d4ed8;
}

.search-form button:active {
    transform: scale(0.97);
}

.search-hints {
    text-align: center;
    margin-top: 14px;
    display: flex;
    gap: 6px;
    justify-content: center;
    flex-wrap: wrap;
    align-items: center;
}

.search-hints span {
    font-size: 13px;
    color: #6b7a8f;
}

.hint-chip {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    font-weight: 500;
    color: #374151;
    background: #ffffff;
    border: 1px solid #dce1e8;
    padding: 4px 14px;
    border-radius: 20px;
    cursor: pointer;
    text-decoration: none;
    transition: all 0.15s;
}

.hint-chip:hover {
    border-color: #2563eb;
    color: #2563eb;
    background: #f0f7ff;
}

/* ─── Alerts ─── */
.alert {
    max-width: 680px;
    margin: 0 auto 16px;
    padding: 16px 20px;
    border-radius: 10px;
    font-size: 14px;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 10px;
}

.alert-error {
    background: #fef2f2;
    border: 1px solid #fecaca;
    color: #dc2626;
}

.alert-success {
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    color: #16a34a;
}

.alert-success .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #16a34a;
    flex-shrink: 0;
}

/* ─── Results ─── */
.results {
    animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(8px); }
    to { opacity: 1; transform: translateY(0); }
}

/* ─── Hero Card ─── */
.hero {
    background: #ffffff;
    border-radius: 16px;
    padding: 28px 32px;
    margin-bottom: 24px;
    border: 1px solid #eaeef2;
    box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 16px 32px;
    align-items: start;
}

.domain {
    font-family: 'JetBrains Mono', monospace;
    font-size: 24px;
    font-weight: 700;
    word-break: break-all;
}

.domain .src {
    font-family: 'Inter', sans-serif;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    color: #2563eb;
    background: #eff6ff;
    padding: 2px 10px;
    border-radius: 4px;
    margin-left: 10px;
    vertical-align: middle;
}

.domain-meta {
    font-size: 13px;
    color: #6b7a8f;
    margin-top: 6px;
}

.domain-meta a {
    color: #2563eb;
    text-decoration: none;
}

.domain-meta a:hover {
    text-decoration: underline;
}

.expiry {
    text-align: right;
    min-width: 100px;
}

.expiry .num {
    font-family: 'JetBrains Mono', monospace;
    font-size: 40px;
    font-weight: 700;
    line-height: 1;
}

.expiry .lbl {
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #6b7a8f;
    margin-top: 2px;
}

.color-ok { color: #16a34a; }
.color-warn { color: #d97706; }
.color-danger { color: #dc2626; }
.color-muted { color: #9aa9b9; }

.expiry-bar {
    grid-column: 1 / -1;
    margin-top: 6px;
}

.expiry-bar .label {
    font-size: 12px;
    color: #6b7a8f;
    margin-bottom: 6px;
    display: flex;
    justify-content: space-between;
}

.expiry-bar .track {
    height: 4px;
    background: #eaeef2;
    border-radius: 4px;
    overflow: hidden;
}

.expiry-bar .fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.8s ease;
}

.fill-ok { background: #16a34a; }
.fill-warn { background: #d97706; }
.fill-danger { background: #dc2626; }
.fill-muted { background: #d1d9e6; }

/* ─── Grid ─── */
.grid-3 {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 20px;
    margin-bottom: 24px;
}

/* ─── Cards ─── */
.card {
    background: #ffffff;
    border-radius: 16px;
    padding: 22px 26px;
    border: 1px solid #eaeef2;
    box-shadow: 0 1px 3px rgba(0,0,0,0.03);
}

.card-head {
    display: flex;
    align-items: center;
    gap: 8px;
    padding-bottom: 14px;
    margin-bottom: 16px;
    border-bottom: 1px solid #eaeef2;
}

.card-head .ico {
    font-size: 16px;
}

.card-title {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: #6b7a8f;
}

.card-title .count {
    font-size: 10px;
    font-weight: 600;
    background: #eff6ff;
    color: #2563eb;
    padding: 1px 10px;
    border-radius: 12px;
    margin-left: 6px;
}

/* ─── Fields ─── */
.field {
    display: grid;
    grid-template-columns: 130px 1fr;
    gap: 4px 14px;
    margin-bottom: 10px;
    align-items: baseline;
}

.field:last-child {
    margin-bottom: 0;
}

.field-lbl {
    font-size: 11px;
    font-weight: 500;
    color: #6b7a8f;
}

.field-val {
    font-size: 13px;
    font-weight: 500;
    color: #1a1a2e;
    word-break: break-all;
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
}

.field-val.mono {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
}

.na {
    color: #9aa9b9;
    font-style: italic;
    font-weight: 400;
}

.tz {
    color: #9aa9b9;
    font-size: 10px;
    font-weight: 400;
}

.dim {
    color: #6b7a8f;
    font-size: 12px;
}

/* ─── Links ─── */
.registrar-link {
    color: #2563eb;
    text-decoration: none;
    font-weight: 600;
    font-size: 12px;
}

.registrar-link:hover {
    text-decoration: underline;
}

/* ─── Badges ─── */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    font-weight: 600;
    text-transform: lowercase;
}

.badge-ok {
    background: #dcfce7;
    color: #16a34a;
}

.badge-warn {
    background: #fef3c7;
    color: #d97706;
}

.badge-danger {
    background: #fee2e2;
    color: #dc2626;
}

.badge-default {
    background: #f3f4f6;
    color: #6b7a8f;
    border: 1px solid #e5e7eb;
}

.badges-wrap {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
}

/* ─── Copy ─── */
.copy-btn {
    background: none;
    border: none;
    cursor: pointer;
    color: #9aa9b9;
    font-size: 12px;
    padding: 1px 4px;
    border-radius: 3px;
    transition: color 0.15s;
}

.copy-btn:hover {
    color: #2563eb;
}

.copy-btn.copied {
    color: #16a34a;
}

/* ─── Tabs ─── */
.tabs {
    background: #ffffff;
    border-radius: 16px;
    border: 1px solid #eaeef2;
    overflow: hidden;
    box-shadow: 0 1px 3px rgba(0,0,0,0.03);
}

.tab-bar {
    display: flex;
    gap: 2px;
    padding: 4px 4px 0;
    background: #f8fafc;
    border-bottom: 1px solid #eaeef2;
    overflow-x: auto;
}

.tab-btn {
    padding: 12px 20px;
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    font-family: 'Inter', sans-serif;
    font-size: 12px;
    font-weight: 600;
    color: #6b7a8f;
    cursor: pointer;
    transition: all 0.15s;
    white-space: nowrap;
}

.tab-btn:hover {
    color: #1a1a2e;
}

.tab-btn.active {
    color: #2563eb;
    border-bottom-color: #2563eb;
}

.tab-pane {
    display: none;
    padding: 24px 28px;
}

.tab-pane.active {
    display: block;
    animation: fadeIn 0.2s ease;
}

/* ─── DNS ─── */
.dns-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 14px;
}

.dns-card {
    background: #f8fafc;
    border: 1px solid #eaeef2;
    border-radius: 10px;
    padding: 14px 18px;
}

.dns-card h4 {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: #6b7a8f;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    gap: 6px;
}

.dns-card h4 .cnt {
    font-size: 9px;
    font-weight: 600;
    color: #9aa9b9;
    background: #ffffff;
    padding: 1px 8px;
    border-radius: 10px;
}

.dns-record {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    font-weight: 500;
    padding: 4px 0;
    border-bottom: 1px solid #eaeef2;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
}

.dns-record:last-child {
    border-bottom: none;
}

.dns-record .prio {
    color: #9aa9b9;
    font-size: 10px;
}

/* ─── Subdomain Table ─── */
.table-wrap {
    overflow-x: auto;
    border: 1px solid #eaeef2;
    border-radius: 10px;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    min-width: 550px;
}

thead th {
    text-align: left;
    padding: 10px 14px;
    background: #f8fafc;
    font-weight: 600;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #6b7a8f;
    border-bottom: 2px solid #eaeef2;
}

tbody td {
    padding: 8px 14px;
    border-bottom: 1px solid #eaeef2;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 500;
    color: #1a1a2e;
}

tbody tr:hover td {
    background: #f8fafc;
}

.td-host {
    font-weight: 600;
}

.td-ip {
    color: #6b7a8f;
}

.td-asn {
    color: #2563eb;
    font-weight: 600;
}

.td-org {
    color: #6b7a8f;
    font-family: 'Inter', sans-serif;
    font-size: 11px;
}

.mini-badge {
    display: inline-block;
    padding: 1px 10px;
    border-radius: 10px;
    font-size: 8px;
    font-weight: 700;
    text-transform: uppercase;
    font-family: 'Inter', sans-serif;
}

.mini-badge-src {
    background: #f3f4f6;
    color: #9aa9b9;
}

/* ─── Raw WHOIS ─── */
pre.raw {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 400;
    color: #374151;
    white-space: pre-wrap;
    word-break: break-word;
    line-height: 1.8;
    max-height: 400px;
    overflow-y: auto;
    padding: 18px;
    background: #f8fafc;
    border: 1px solid #eaeef2;
    border-radius: 10px;
}

/* ─── Collapsible ─── */
.collapse-toggle {
    width: 100%;
    background: none;
    border: none;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 0;
    cursor: pointer;
    font-family: 'Inter', sans-serif;
    font-size: 13px;
    font-weight: 600;
    color: #1a1a2e;
}

.collapse-toggle .chevron {
    transition: transform 0.2s;
    color: #9aa9b9;
    font-size: 11px;
}

.collapse-toggle.open .chevron {
    transform: rotate(180deg);
}

.collapse-body {
    display: none;
}

.collapse-body.open {
    display: block;
    animation: fadeIn 0.2s ease;
}

/* ─── Footer ─── */
.footer {
    text-align: center;
    margin-top: 48px;
    padding-top: 24px;
    border-top: 1px solid #eaeef2;
    color: #9aa9b9;
    font-size: 12px;
}

/* ─── Responsive ─── */
@media (max-width: 640px) {
    .container {
        padding: 16px 12px 40px;
    }

    .header {
        padding: 24px 16px 28px;
    }

    .header h1 {
        font-size: 24px;
    }

    .hero {
        grid-template-columns: 1fr;
        padding: 20px 22px;
    }

    .expiry {
        text-align: left;
    }

    .search-form {
        flex-direction: column;
        background: transparent;
        padding: 0;
        border: none;
        box-shadow: none;
    }

    .search-form input {
        background: #ffffff;
        border: 2px solid #dce1e8;
        border-radius: 12px;
        padding: 16px;
    }

    .search-form input:focus {
        border-color: #2563eb;
    }

    .search-form button {
        padding: 16px;
        border-radius: 12px;
    }

    .field {
        grid-template-columns: 1fr;
        gap: 0;
    }

    .grid-3 {
        grid-template-columns: 1fr;
    }

    .dns-grid {
        grid-template-columns: 1fr;
    }

    .tab-btn {
        padding: 10px 14px;
        font-size: 11px;
    }

    .tab-pane {
        padding: 16px;
    }

    .card {
        padding: 18px 20px;
    }
}
</style>
</head>
<body>

<div class="container">

    <!-- Header -->
    <header class="header">
        <div class="logo">🔍 <span>Domain</span> Intelligence</div>
        <h1>WHOIS &amp; <span>DNS Lookup</span></h1>
        <p class="sub">Professional domain intelligence — 500+ TLDs supported</p>
    </header>

    <!-- Search -->
    <div class="search-wrap">
        <form method="POST" class="search-form" id="searchForm" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="text"
                   name="domain"
                   id="domainInput"
                   placeholder="example.com  ·  example.co.ug"
                   value="<?= htmlspecialchars($domain) ?>"
                   required
                   spellcheck="false"
                   maxlength="253">
            <button type="submit" id="submitBtn">Look up</button>
        </form>
       
    </div>

    <?php if ($error): ?>
        <div class="alert alert-error">⚠ <?= $error ?></div>
    <?php endif; ?>

    <?php if ($isAvailable && $domain && !$error): ?>
        <div class="alert alert-success" id="resultsAnchor">
            <div class="dot"></div>
            <strong><?= htmlspecialchars($domain) ?></strong> appears to be available for registration!
        </div>
    <?php endif; ?>

    <?php if ($result && !$isAvailable):
        $days = $result['days'] ?? null;
        $color = colorClass($days);
        $barPct = $days !== null ? min(100, max(0, round(max($days, 0) / 730 * 100))) : 0;
        $dns = $dnsRecords ?? [];
        $timeLeft = $result['time_left'] ?? null;
        $age = $result['age'] ?? null;
        $registrarUrl = $result['registrar_url'] ?? null;
    ?>
    <div class="results" id="resultsAnchor">

        <!-- Hero -->
        <div class="hero">
            <div>
                <div class="domain">
                    <?= htmlspecialchars($result['domain']) ?>
                    <span class="src"><?= htmlspecialchars($result['source']) ?></span>
                </div>
                <div class="domain-meta">
                    <?php if (!empty($result['registrar'])): ?>
                        Registrar:
                        <?php if ($registrarUrl): ?>
                            <a href="<?= htmlspecialchars($registrarUrl) ?>" target="_blank" rel="noopener"><?= htmlspecialchars($result['registrar']) ?></a>
                        <?php else: ?>
                            <?= htmlspecialchars($result['registrar']) ?>
                        <?php endif; ?>
                    <?php endif; ?>
                    <?php if ($age): ?>
                        &nbsp;·&nbsp; Age: <?= htmlspecialchars($age) ?>
                    <?php endif; ?>
                </div>
            </div>
            <div class="expiry">
                <div class="num color-<?= $color ?>">
                    <?php if ($days !== null): ?>
                        <?= $days < 0 ? '-' . abs($days) : $days ?>
                    <?php else: ?>
                        —
                    <?php endif; ?>
                </div>
                <div class="lbl">
                    <?= $days === null ? 'days unknown' : ($days < 0 ? 'days expired' : 'days left') ?>
                </div>
            </div>
            <div class="expiry-bar">
                <div class="label">
                    <span>Expiry: <?= fmtDate($result['expiry'] ?? null) ?></span>
                    <?php if ($timeLeft && $timeLeft !== 'Expired'): ?>
                        <span class="dim"><?= htmlspecialchars($timeLeft) ?> remaining</span>
                    <?php endif; ?>
                </div>
                <div class="track">
                    <div class="fill fill-<?= $color ?>" style="width: <?= $barPct ?>%"></div>
                </div>
            </div>
        </div>

        <!-- Grid -->
        <div class="grid-3">

            <!-- Dates -->
            <div class="card">
                <div class="card-head"><span class="ico">📅</span><span class="card-title">Registration Dates</span></div>
                <div class="field"><span class="field-lbl">Created</span><span class="field-val"><?= fmtDate($result['created'] ?? null) ?></span></div>
                <div class="field"><span class="field-lbl">Updated</span><span class="field-val"><?= fmtDate($result['updated'] ?? null) ?></span></div>
                <div class="field"><span class="field-lbl">Expiry</span><span class="field-val"><?= fmtDate($result['expiry'] ?? null) ?></span></div>
                <?php if ($age): ?>
                <div class="field"><span class="field-lbl">Domain Age</span><span class="field-val dim"><?= htmlspecialchars($age) ?></span></div>
                <?php endif; ?>
                <?php if (!empty($result['dnssec'])): ?>
                <div class="field"><span class="field-lbl">DNSSEC</span><span class="field-val"><?= htmlspecialchars($result['dnssec']) ?></span></div>
                <?php endif; ?>
            </div>

            <!-- Registrar -->
            <div class="card">
                <div class="card-head"><span class="ico">🏢</span><span class="card-title">Registrar</span></div>
                <div class="field">
                    <span class="field-lbl">Registrar</span>
                    <span class="field-val">
                        <?php if (!empty($result['registrar'])): ?>
                            <?= htmlspecialchars($result['registrar']) ?>
                            <?php if ($registrarUrl): ?>
                                <a href="<?= htmlspecialchars($registrarUrl) ?>" target="_blank" rel="noopener" class="registrar-link">↗</a>
                            <?php endif; ?>
                        <?php else: ?>
                            <span class="na">Not disclosed</span>
                        <?php endif; ?>
                    </span>
                </div>
                <div class="field">
                    <span class="field-lbl">Registrar URL</span>
                    <span class="field-val">
                        <?php if ($registrarUrl): ?>
                            <a href="<?= htmlspecialchars($registrarUrl) ?>" target="_blank" rel="noopener" class="registrar-link">
                                <?= htmlspecialchars($registrarUrl) ?>
                            </a>
                        <?php else: ?>
                            <span class="na">Not available</span>
                        <?php endif; ?>
                    </span>
                </div>
                <div class="field">
                    <span class="field-lbl">Domain Availability</span>
                    <span class="field-val">
                        <?php if (isDomainAvailable($result)): ?>
                            <span class="badge badge-ok">Available</span>
                        <?php else: ?>
                            <span class="badge badge-default">Registered</span>
                        <?php endif; ?>
                    </span>
                </div>
            </div>

            <!-- Domain lifecycle -->
            <div class="card">
                <div class="card-head"><span class="ico">⏳</span><span class="card-title">Domain Lifecycle</span></div>

                <div class="lifecycle-wrap">
                    <div class="lifecycle-step">
                        <span class="step-name">Registered</span>
                        <span class="step-duration">— Until expiry (variable)</span>
                    </div>
                    <div class="lifecycle-step">
                        <span class="step-name">Expired</span>
                        <span class="step-duration">— Immediate after expiry</span>
                    </div>
                    <div class="lifecycle-step">
                        <span class="step-name">Grace Period</span>
                        <span class="step-duration">— 0–45 days (registrar dependent)</span>
                    </div>
                    <div class="lifecycle-step">
                        <span class="step-name">Redemption</span>
                        <span class="step-duration">— ~30 days (restorable)</span>
                    </div>
                    <div class="lifecycle-step">
                        <span class="step-name">Pending Delete</span>
                        <span class="step-duration">— 5 days</span>
                    </div>
                    <div class="lifecycle-step">
                        <span class="step-name">Available</span>
                        <span class="step-duration">— Becomes available for registration</span>
                    </div>
                </div>

                <?php if (!empty($result['nameservers'])): ?>
                <div style="margin-top: 16px;">
                    <div class="card-head" style="padding-bottom: 10px; margin-bottom: 12px;">
                        <span class="ico">🌐</span>
                        <span class="card-title">Nameservers <span class="count"><?= count($result['nameservers']) ?></span></span>
                    </div>
                    <?php foreach ($result['nameservers'] as $ns): ?>
                    <div class="field">
                        <span class="field-lbl">NS</span>
                        <span class="field-val mono">
                            <?= htmlspecialchars($ns) ?>
                            <button class="copy-btn" data-copy="<?= htmlspecialchars($ns) ?>" title="Copy">📋</button>
                        </span>
                    </div>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Tabs -->
        <div class="tabs">
            <div class="tab-bar">
                <button class="tab-btn active" data-tab="dns">DNS Records</button>
                <?php if (!empty($subdomains)): ?>
                <button class="tab-btn" data-tab="subs">Subdomains <span class="count"><?= count($subdomains) ?></span></button>
                <?php endif; ?>
                <button class="tab-btn" data-tab="contacts">Contacts</button>
                <?php if (!empty($result['raw'])): ?>
                <button class="tab-btn" data-tab="raw">Raw WHOIS</button>
                <?php endif; ?>
            </div>

            <!-- DNS -->
            <div class="tab-pane active" id="tab-dns">
                <?php if (!empty($dns)): ?>
                <div class="dns-grid">
                    <?php if (!empty($dns['A'])): ?>
                    <div class="dns-card">
                        <h4>A Records <span class="cnt"><?= count($dns['A']) ?></span></h4>
                        <?php foreach ($dns['A'] as $r): ?>
                        <div class="dns-record"><span><?= htmlspecialchars($r['ip']) ?></span><button class="copy-btn" data-copy="<?= htmlspecialchars($r['ip']) ?>" title="Copy">📋</button></div>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                    <?php if (!empty($dns['AAAA'])): ?>
                    <div class="dns-card">
                        <h4>AAAA Records <span class="cnt"><?= count($dns['AAAA']) ?></span></h4>
                        <?php foreach ($dns['AAAA'] as $r): ?>
                        <div class="dns-record"><span><?= htmlspecialchars($r['ip']) ?></span><button class="copy-btn" data-copy="<?= htmlspecialchars($r['ip']) ?>" title="Copy">📋</button></div>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                    <?php if (!empty($dns['MX'])): ?>
                    <div class="dns-card">
                        <h4>MX Records <span class="cnt"><?= count($dns['MX']) ?></span></h4>
                        <?php foreach ($dns['MX'] as $r): ?>
                        <div class="dns-record"><span><?= htmlspecialchars($r['target']) ?></span><span class="prio">pri <?= $r['pri'] ?></span></div>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                    <?php if (!empty($dns['NS'])): ?>
                    <div class="dns-card">
                        <h4>NS Records <span class="cnt"><?= count($dns['NS']) ?></span></h4>
                        <?php foreach ($dns['NS'] as $r): ?>
                        <div class="dns-record"><span><?= htmlspecialchars($r['target']) ?></span><button class="copy-btn" data-copy="<?= htmlspecialchars($r['target']) ?>" title="Copy">📋</button></div>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                    <?php if (!empty($dns['TXT'])): ?>
                    <div class="dns-card" style="grid-column: 1 / -1;">
                        <h4>TXT Records <span class="cnt"><?= count($dns['TXT']) ?></span></h4>
                        <?php foreach ($dns['TXT'] as $r): ?>
                        <div class="dns-record" style="word-break: break-all;"><span><?= htmlspecialchars($r['txt']) ?></span></div>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                    <?php if (!empty($dns['CNAME'])): ?>
                    <div class="dns-card"><h4>CNAME</h4><div class="dns-record"><?= htmlspecialchars($dns['CNAME']['target']) ?></div></div>
                    <?php endif; ?>
                </div>
                <?php else: ?>
                    <p class="na" style="padding: 12px 0;">No DNS records found.</p>
                <?php endif; ?>
            </div>

            <!-- Subdomains -->
            <?php if (!empty($subdomains)): ?>
            <div class="tab-pane" id="tab-subs">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
                    <span style="font-weight: 600; font-size: 13px;">Discovered Subdomains</span>
                    <span style="font-size: 12px; color: #6b7a8f; background: #f3f4f6; padding: 2px 14px; border-radius: 12px;"><?= count($subdomains) ?> found</span>
                </div>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Hostname</th><th>IP Address</th><th>ASN</th><th>Organisation</th><th>Source</th></tr></thead>
                        <tbody>
                        <?php foreach ($subdomains as $host => $info): ?>
                            <tr>
                                <td class="td-host"><?= htmlspecialchars($host) ?></td>
                                <td class="td-ip"><?= !empty($info['ip']) ? htmlspecialchars($info['ip']) : '<span class="na">—</span>' ?></td>
                                <td class="td-asn"><?= !empty($info['asn']) ? htmlspecialchars($info['asn']) : '<span class="na">—</span>' ?></td>
                                <td class="td-org"><?= !empty($info['asn_name']) ? htmlspecialchars($info['asn_name']) : '<span class="na">—</span>' ?></td>
                                <td><span class="mini-badge mini-badge-src"><?= htmlspecialchars($info['source'] ?? 'DNS') ?></span></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
            <?php endif; ?>

            <!-- Contacts -->
            <div class="tab-pane" id="tab-contacts">
                <div class="grid-3" style="margin-bottom: 0;">
                    <div>
                        <div style="font-weight: 600; font-size: 12px; margin-bottom: 10px;">👤 Registrant</div>
                        <div class="field"><span class="field-lbl">Name</span><span class="field-val"><?= !empty($result['registrant']) ? htmlspecialchars($result['registrant']) : '<span class="na">Redacted</span>' ?></span></div>
                        <div class="field"><span class="field-lbl">Organisation</span><span class="field-val"><?= !empty($result['registrant_org']) ? htmlspecialchars($result['registrant_org']) : '<span class="na">—</span>' ?></span></div>
                        <div class="field"><span class="field-lbl">Email</span><span class="field-val mono"><?= !empty($result['registrant_email']) ? htmlspecialchars($result['registrant_email']) : '<span class="na">—</span>' ?></span></div>
                        <div class="field"><span class="field-lbl">Phone</span><span class="field-val mono"><?= !empty($result['registrant_phone']) ? htmlspecialchars($result['registrant_phone']) : '<span class="na">—</span>' ?></span></div>
                        <div class="field"><span class="field-lbl">Country</span><span class="field-val"><?= !empty($result['registrant_country']) ? htmlspecialchars($result['registrant_country']) : '<span class="na">—</span>' ?></span></div>
                    </div>
                    <div>
                        <div style="font-weight: 600; font-size: 12px; margin-bottom: 10px;">🔧 Admin Contact</div>
                        <div class="field"><span class="field-lbl">Name</span><span class="field-val"><?= !empty($result['admin']) ? htmlspecialchars($result['admin']) : '<span class="na">—</span>' ?></span></div>
                        <div class="field"><span class="field-lbl">Email</span><span class="field-val mono"><?= !empty($result['admin_email']) ? htmlspecialchars($result['admin_email']) : '<span class="na">—</span>' ?></span></div>
                    </div>
                    <div>
                        <div style="font-weight: 600; font-size: 12px; margin-bottom: 10px;">⚙️ Tech Contact</div>
                        <div class="field"><span class="field-lbl">Name</span><span class="field-val"><?= !empty($result['tech']) ? htmlspecialchars($result['tech']) : '<span class="na">—</span>' ?></span></div>
                        <div class="field"><span class="field-lbl">Email</span><span class="field-val mono"><?= !empty($result['tech_email']) ? htmlspecialchars($result['tech_email']) : '<span class="na">—</span>' ?></span></div>
                    </div>
                </div>
            </div>

            <!-- Raw WHOIS -->
            <?php if (!empty($result['raw'])): ?>
            <div class="tab-pane" id="tab-raw">
                <button class="collapse-toggle open" id="rawToggle">
                    <span>Raw WHOIS Response</span>
                    <span class="chevron">▼</span>
                </button>
                <div class="collapse-body open" id="rawBody">
                    <pre class="raw"><?= htmlspecialchars($result['raw']) ?></pre>
                </div>
            </div>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>

    <footer class="footer">Domain Intelligence Checker · WHOIS + RDAP + DNS</footer>

</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    var input = document.getElementById('domainInput');
    if (input && !input.value) input.focus();

    document.querySelectorAll('.hint-chip[data-domain]').forEach(function(chip) {
        chip.addEventListener('click', function(e) {
            e.preventDefault();
            input.value = this.dataset.domain;
            document.getElementById('searchForm').submit();
        });
    });

    document.querySelectorAll('.tab-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var tab = this.dataset.tab;
            var block = this.closest('.tabs');
            block.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
            block.querySelectorAll('.tab-pane').forEach(function(p) { p.classList.remove('active'); });
            this.classList.add('active');
            var pane = document.getElementById('tab-' + tab);
            if (pane) pane.classList.add('active');
        });
    });

    document.querySelectorAll('.copy-btn[data-copy]').forEach(function(btn) {
        btn.addEventListener('click', function() {
            try {
                navigator.clipboard.writeText(this.dataset.copy).then(function() {
                    btn.textContent = '✓';
                    btn.classList.add('copied');
                    setTimeout(function() {
                        btn.textContent = '📋';
                        btn.classList.remove('copied');
                    }, 1500);
                });
            } catch (e) {
                var textarea = document.createElement('textarea');
                textarea.value = this.dataset.copy;
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
                btn.textContent = '✓';
                btn.classList.add('copied');
                setTimeout(function() {
                    btn.textContent = '📋';
                    btn.classList.remove('copied');
                }, 1500);
            }
        });
    });

    var rawToggle = document.getElementById('rawToggle');
    var rawBody = document.getElementById('rawBody');
    if (rawToggle && rawBody) {
        rawToggle.addEventListener('click', function() {
            this.classList.toggle('open');
            rawBody.classList.toggle('open');
        });
    }

    document.querySelectorAll('.fill').forEach(function(bar) {
        var w = bar.style.width;
        bar.style.width = '0%';
        requestAnimationFrame(function() {
            setTimeout(function() {
                bar.style.width = w;
            }, 300);
        });
    });
});
</script>

</body>
</html>