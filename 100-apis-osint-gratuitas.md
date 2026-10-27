# 100 APIs OSINT Gratuitas ou com Free Tier

Lista curada de APIs para um agregador OSINT. **Gratuita** inclui APIs totalmente gratuitas e serviços com free tier utilizável. Limites, autenticação e condições podem mudar; valide sempre os termos de uso antes de automatizar.

**Regra de uso:** não utilize estas APIs para acessar, armazenar ou redistribuir dumps brutos de credenciais, senhas em texto claro ou dados pessoais sem base legal, finalidade legítima e controles de acesso.

| # | API | URL | Categoria | O que fornece | Modelo | Chave |
|---:|---|---|---|---|---|---|
| 1 | **RDAP / IANA Bootstrap** | https://rdap.org/ | Domínios | Registro e contatos técnicos de domínios via RDAP | Gratuito | Nenhuma |
| 2 | **IANA RDAP Bootstrap** | https://data.iana.org/rdap/dns.json | Domínios | Endpoints RDAP oficiais por TLD | Gratuito | Nenhuma |
| 3 | **Google DNS-over-HTTPS** | https://dns.google/resolve?name=example.com&type=A | DNS | Resolução DNS pública via HTTPS | Gratuito | Nenhuma |
| 4 | **Cloudflare DNS-over-HTTPS** | https://cloudflare-dns.com/dns-query | DNS | Resolução DNS pública via DoH | Gratuito | Nenhuma |
| 5 | **DNSDumpster** | https://dnsdumpster.com/ | DNS | Mapa de DNS, MX, NS e subdomínios | Freemium | Opcional |
| 6 | **HackerTarget** | https://hackertarget.com/ | Rede/DNS | DNS, WHOIS, portas, subdomínios e reconhecimento | Freemium | Opcional |
| 7 | **crt.sh** | https://crt.sh/ | Certificados | Certificate Transparency e subdomínios | Gratuito | Nenhuma |
| 8 | **Cert Spotter** | https://sslmate.com/certspotter/ | Certificados | Monitoramento de certificados TLS e CT logs | Freemium | Opcional |
| 9 | **CertStream** | https://certstream.calidog.io/ | Certificados | Stream em tempo real de certificados emitidos | Gratuito | Nenhuma |
| 10 | **SecurityTrails** | https://securitytrails.com/ | Domínios | Histórico DNS, subdomínios e WHOIS | Freemium | Obrigatória |
| 11 | **ViewDNS.info** | https://viewdns.info/ | DNS | DNS reverso, WHOIS, IP e ferramentas de domínio | Freemium | Opcional |
| 12 | **Robtex** | https://www.robtex.com/ | DNS/Rede | DNS, IP, ASN e relações de infraestrutura | Freemium | Opcional |
| 13 | **RapidDNS** | https://rapiddns.io/ | Subdomínios | Subdomínios e registros DNS históricos | Gratuito | Nenhuma |
| 14 | **Subdomain Center** | https://api.subdomain.center/ | Subdomínios | Enumeração passiva de subdomínios | Gratuito | Nenhuma |
| 15 | **Chaos ProjectDiscovery** | https://chaos.projectdiscovery.io/ | Subdomínios | Banco público de subdomínios | Freemium | Opcional |
| 16 | **DomainTools WHOIS** | https://www.domaintools.com/ | WHOIS | WHOIS histórico e inteligência de domínio | Freemium | Obrigatória |
| 17 | **WhoisXML API** | https://whoisxmlapi.com/ | WHOIS | WHOIS, DNS, subdomínios e inteligência de domínio | Freemium | Obrigatória |
| 18 | **Shodan** | https://developer.shodan.io/ | Infraestrutura | Dispositivos expostos, portas, banners, CVEs e busca na internet | Freemium | Obrigatória |
| 19 | **Shodan InternetDB** | https://internetdb.shodan.io/ | Infraestrutura | Consulta rápida de portas, hosts e vulnerabilidades por IP | Gratuito | Nenhuma |
| 20 | **Censys Search** | https://search.censys.io/ | Infraestrutura | Hosts, certificados, serviços e superfície de ataque | Freemium | Obrigatória |
| 21 | **ZoomEye** | https://www.zoomeye.org/ | Infraestrutura | Busca de dispositivos, serviços e ativos expostos | Freemium | Obrigatória |
| 22 | **Fofa** | https://fofa.info/ | Infraestrutura | Busca de ativos, serviços e tecnologias expostas | Freemium | Obrigatória |
| 23 | **Netlas** | https://netlas.io/ | Infraestrutura | Inventário de ativos, DNS, certificados e serviços | Freemium | Obrigatória |
| 24 | **Criminal IP** | https://www.criminalip.io/ | IP/Threat Intel | Reputação de IP, domínio e superfície de ataque | Freemium | Obrigatória |
| 25 | **GreyNoise** | https://www.greynoise.io/ | Threat Intel | Classificação de scanners e ruído na internet | Freemium | Obrigatória |
| 26 | **AbuseIPDB** | https://www.abuseipdb.com/ | IP/Abuso | Reputação e denúncias de abuso por IP | Freemium | Obrigatória |
| 27 | **IPinfo** | https://ipinfo.io/developers | IP/Geolocalização | Geolocalização, ASN, ISP, empresa e tipo de rede | Freemium | Opcional |
| 28 | **ip-api** | https://ip-api.com/ | IP/Geolocalização | Geolocalização de IP, ASN e organização | Gratuito | Nenhuma |
| 29 | **ipapi.co** | https://ipapi.co/api/ | IP/Geolocalização | Geolocalização, moeda, fuso e rede do IP | Freemium | Opcional |
| 30 | **IP2Location** | https://www.ip2location.io/ | IP/Geolocalização | Geolocalização, proxy, VPN e risco de IP | Freemium | Obrigatória |
| 31 | **MaxMind GeoIP2** | https://www.maxmind.com/en/geoip2-databases | IP/Geolocalização | Geolocalização e dados de rede | Freemium | Opcional |
| 32 | **BGPView** | https://bgpview.io/api | ASN/BGP | ASN, prefixos, peers e dados BGP | Gratuito | Nenhuma |
| 33 | **RIPEstat** | https://stat.ripe.net/docs/02.api/ | ASN/BGP | Roteamento, ASN, DNS e histórico de rede | Gratuito | Nenhuma |
| 34 | **PeeringDB** | https://www.peeringdb.com/apidocs/ | Rede | IXPs, data centers, ASNs e políticas de peering | Gratuito | Opcional |
| 35 | **Hurricane Electric BGP Toolkit** | https://bgp.he.net/ | ASN/BGP | ASN, prefixos, peers e roteamento | Gratuito | Nenhuma |
| 36 | **IPQualityScore** | https://www.ipqualityscore.com/ | IP/Fraude | Proxy, VPN, TOR, fraude e reputação de IP | Freemium | Obrigatória |
| 37 | **MxToolbox** | https://mxtoolbox.com/ | E-mail/DNS | MX, SPF, DKIM, DMARC e blacklists | Freemium | Opcional |
| 38 | **urlscan.io** | https://urlscan.io/docs/api/ | URLs | Análise de URLs, screenshots, tecnologias e infraestrutura | Freemium | Opcional |
| 39 | **VirusTotal** | https://docs.virustotal.com/ | Threat Intel | Reputação de URL, domínio, IP e hash de arquivo | Freemium | Obrigatória |
| 40 | **AlienVault OTX** | https://otx.alienvault.com/api | Threat Intel | IOCs, pulses e threat intelligence | Gratuito | Obrigatória |
| 41 | **MISP** | https://www.misp-project.org/ | Threat Intel | Compartilhamento e consulta de IOC | Gratuito | Depende da instância |
| 42 | **ThreatFox** | https://threatfox.abuse.ch/api/ | Threat Intel | IOCs de malware e campanhas | Gratuito | Obrigatória |
| 43 | **URLhaus** | https://urlhaus.abuse.ch/api/ | Malware | URLs maliciosas e distribuição de malware | Gratuito | Nenhuma |
| 44 | **MalwareBazaar** | https://bazaar.abuse.ch/api/ | Malware | Amostras, hashes e metadados de malware | Gratuito | Opcional |
| 45 | **Feodo Tracker** | https://feodotracker.abuse.ch/ | Malware | C2 de botnets e IOCs | Gratuito | Nenhuma |
| 46 | **Wayback Machine** | https://archive.org/wayback/available?url=example.com | Web/Histórico | Snapshots históricos de páginas | Gratuito | Nenhuma |
| 47 | **Common Crawl** | https://commoncrawl.org/ | Web/Histórico | Corpus massivo de páginas web rastreadas | Gratuito | Nenhuma |
| 48 | **HTTP Archive** | https://httparchive.org/ | Web | Histórico técnico de sites e desempenho | Gratuito | Nenhuma |
| 49 | **BuiltWith** | https://builtwith.com/ | Tecnologias | Tecnologias usadas por sites | Freemium | Obrigatória |
| 50 | **Wappalyzer** | https://www.wappalyzer.com/ | Tecnologias | Identificação de stack tecnológica | Freemium | Opcional |
| 51 | **GitHub API** | https://docs.github.com/rest | Código/Pessoas | Usuários, repositórios, commits, organizações e código público | Freemium | Opcional |
| 52 | **GitLab API** | https://docs.gitlab.com/ee/api/ | Código/Pessoas | Projetos, usuários, grupos e repositórios públicos | Freemium | Opcional |
| 53 | **Sourcegraph** | https://sourcegraph.com/ | Código | Busca de código público e segredos expostos | Freemium | Opcional |
| 54 | **Gitleaks** | https://github.com/gitleaks/gitleaks | Segredos | Detecção de credenciais em repositórios Git | Gratuito | Nenhuma |
| 55 | **TruffleHog** | https://github.com/trufflesecurity/trufflehog | Segredos | Varredura de segredos em repositórios e histórico Git | Gratuito | Nenhuma |
| 56 | **Have I Been Pwned** | https://haveibeenpwned.com/API/v3 | Vazamentos | Exposição de e-mail, senha e domínio em breaches | Freemium | Obrigatória |
| 57 | **Intelligence X** | https://intelx.io/ | Vazamentos/Web | Leaks, pastes, dark web, documentos e histórico | Freemium | Obrigatória |
| 58 | **DeHashed** | https://www.dehashed.com/ | Vazamentos | Busca ampla em registros de vazamento | Freemium | Obrigatória |
| 59 | **LeakCheck** | https://leakcheck.io/ | Vazamentos | Busca por e-mail, username, domínio e senha | Freemium | Obrigatória |
| 60 | **BreachDirectory** | https://breachdirectory.org/ | Vazamentos | Consulta de credenciais e domínios em breaches | Freemium | Opcional |
| 61 | **Snusbase** | https://snusbase.com/ | Vazamentos | Busca em bases de vazamento e stealer logs | Freemium | Obrigatória |
| 62 | **Hudson Rock** | https://www.hudsonrock.com/ | Vazamentos | Exposição corporativa em infostealers | Freemium | Opcional |
| 63 | **Holehe** | https://github.com/megadose/holehe | E-mail | Verificação de registro de e-mail em serviços | Gratuito | Nenhuma |
| 64 | **Gravatar** | https://docs.wordpress.com/rest-api/ | E-mail/Avatar | Avatar e perfil público associado a e-mail | Gratuito | Nenhuma |
| 65 | **Hunter.io** | https://hunter.io/api-documentation | E-mail/Empresa | Descoberta e verificação de e-mails corporativos | Freemium | Obrigatória |
| 66 | **Tomba** | https://tomba.io/api | E-mail/Empresa | E-mails corporativos, verificação e enriquecimento | Freemium | Obrigatória |
| 67 | **Sherlock** | https://github.com/sherlock-project/sherlock | Usernames | Enumeração de username em centenas de plataformas | Gratuito | Nenhuma |
| 68 | **Maigret** | https://github.com/soxoj/maigret | Usernames | Busca de contas por username em fontes públicas | Gratuito | Nenhuma |
| 69 | **WhatsMyName** | https://whatsmyname.app/ | Usernames | Enumeração de usernames em redes sociais | Gratuito | Nenhuma |
| 70 | **Social Searcher** | https://www.social-searcher.com/ | SOCMINT | Busca pública em redes sociais | Freemium | Opcional |
| 71 | **Bluesky API** | https://docs.bsky.app/ | SOCMINT | Perfis, posts, seguidores e busca pública | Gratuito | Opcional |
| 72 | **Mastodon API** | https://docs.joinmastodon.org/api/ | SOCMINT | Perfis, posts e instâncias públicas | Gratuito | Opcional |
| 73 | **Reddit API** | https://www.reddit.com/dev/api/ | SOCMINT | Usuários, subreddits, posts e comentários públicos | Freemium | Obrigatória |
| 74 | **Telegram Bot API** | https://core.telegram.org/bots/api | SOCMINT | Automação e coleta em canais/bots autorizados | Gratuito | Obrigatória |
| 75 | **Discord API** | https://discord.com/developers/docs | SOCMINT | Servidores, canais e usuários acessíveis | Freemium | Obrigatória |
| 76 | **TikTok Research API** | https://developers.tiktok.com/products/research-api/ | SOCMINT | Pesquisa de conteúdo público | Freemium | Obrigatória |
| 77 | **YouTube Data API** | https://developers.google.com/youtube/v3 | SOCMINT | Canais, vídeos, comentários e metadados públicos | Freemium | Obrigatória |
| 78 | **Twitch API** | https://dev.twitch.tv/docs/api/ | SOCMINT | Canais, streams, usuários e clips | Freemium | Obrigatória |
| 79 | **GitHub Search API** | https://docs.github.com/rest/search | Código/Pessoas | Busca de usuários, código, commits e organizações | Freemium | Opcional |
| 80 | **Keybase API** | https://keybase.io/docs/api/1.0/call | Identidade | Identidades criptográficas e provas sociais | Gratuito | Nenhuma |
| 81 | **Gravatar Profiles** | https://api.gravatar.com/v3/profiles/ | E-mail/Identidade | Perfil público vinculado a hash de e-mail | Gratuito | Nenhuma |
| 82 | **OpenStreetMap Nominatim** | https://nominatim.org/release-docs/latest/api/Search/ | GEOINT | Geocodificação e busca de endereços/POIs | Gratuito | Nenhuma |
| 83 | **OpenStreetMap Overpass API** | https://wiki.openstreetmap.org/wiki/Overpass_API | GEOINT | Consulta estruturada de dados do mapa | Gratuito | Nenhuma |
| 84 | **Open-Meteo Geocoding** | https://open-meteo.com/en/docs/geocoding-api | GEOINT | Geocodificação gratuita de localidades | Gratuito | Nenhuma |
| 85 | **Google Maps Geocoding** | https://developers.google.com/maps/documentation/geocoding | GEOINT | Geocodificação e Places | Freemium | Obrigatória |
| 86 | **Mapbox Geocoding** | https://docs.mapbox.com/api/search/geocoding/ | GEOINT | Geocodificação, endereços e POIs | Freemium | Obrigatória |
| 87 | **Mapillary** | https://www.mapillary.com/developer/api-documentation/ | GEOINT | Imagens street-level e metadados | Freemium | Obrigatória |
| 88 | **Copernicus Data Space** | https://documentation.dataspace.copernicus.eu/ | GEOINT | Imagens de satélite Sentinel | Gratuito | Obrigatória |
| 89 | **NASA Earthdata** | https://www.earthdata.nasa.gov/ | GEOINT | Imagens de satélite, clima e observação da Terra | Gratuito | Obrigatória |
| 90 | **USGS Earth Explorer** | https://earthexplorer.usgs.gov/ | GEOINT | Imagens de satélite e dados geoespaciais | Gratuito | Obrigatória |
| 91 | **Sentinel Hub** | https://www.sentinel-hub.com/develop/api/ | GEOINT | Processamento e acesso a imagens de satélite | Freemium | Obrigatória |
| 92 | **OpenAerialMap** | https://openaerialmap.org/ | GEOINT | Imagens aéreas abertas | Gratuito | Nenhuma |
| 93 | **SunCalc** | https://github.com/torinmb/suncalc | GEOINT | Posição solar para verificação de horário | Gratuito | Nenhuma |
| 94 | **TinEye** | https://tineye.com/ | Imagens | Busca reversa de imagens | Freemium | Obrigatória |
| 95 | **Google Vision API** | https://cloud.google.com/vision/docs | Imagens | OCR, objetos, texto e landmarks | Freemium | Obrigatória |
| 96 | **Clarifai** | https://docs.clarifai.com/ | Imagens | Reconhecimento visual e classificação | Freemium | Obrigatória |
| 97 | **Sightengine** | https://sightengine.com/ | Imagens | Moderação, objetos e análise de mídia | Freemium | Obrigatória |
| 98 | **ExifTool** | https://exiftool.org/ | Mídia | Metadados EXIF de imagens e vídeos | Gratuito | Nenhuma |
| 99 | **Metadefender** | https://www.opswat.com/technologies/metadefender | Arquivos | Análise de arquivos e metadados | Freemium | Obrigatória |
| 100 | **Hybrid Analysis** | https://www.hybrid-analysis.com/ | Malware | Análise sandbox de arquivos suspeitos | Freemium | Obrigatória |

## Prioridade para o MVP

Para um agregador inicial de e-mail, domínio, IP e exposição:
1. Have I Been Pwned
2. Intelligence X
3. DeHashed
4. Shodan / Shodan InternetDB
5. Censys
6. VirusTotal
7. urlscan.io
8. crt.sh
9. RDAP/WHOIS
10. Google/Cloudflare DNS-over-HTTPS
11. IPinfo ou ip-api
12. AbuseIPDB
13. Wayback Machine
14. GitHub API
15. Sherlock/Maigret para usernames

## Observações de integração

- **Sem chave:** RDAP, DNS-over-HTTPS, crt.sh, CertStream, Wayback, BGPView, RIPEstat, OpenSanctions, CourtListener, USAspending e SEC EDGAR.
- **Free tier com chave:** Shodan, Censys, VirusTotal, urlscan, HIBP, AbuseIPDB, IPinfo, SecurityTrails, Hunter.io e Intelligence X.
- **Rate limit:** implemente cache, fila, backoff exponencial e circuit breaker por fonte.
- **Proveniência:** guarde URL, timestamp, payload bruto, hash, versão do adapter e nível de confiança.
- **Vazamentos:** prefira APIs licenciadas; evite ingestão de dumps brutos e não exponha senhas em texto claro.