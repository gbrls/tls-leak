# tls-leak
Domain discovery via TLS connections.

The main idea in this tool is to obtain domain information via the data that's sent via the TLS certificates. 
This is not the same as searching in the certificate transparency data like other tools do.

# Usage

```
~ ❯ tls-leak --help                                                                                                                                          23:47:00
Usage: tls-leak <domain> [--port <port>] [--validity <validity>] [--all <all>] [--timeout <timeout>]

TLS client to extract data from servers

Positional Arguments:
  domain

Options:
  --port            port to try the TLS handshake
  --validity        check validity of the certificates
  --all             displays all information gathered via TLS in JSON format
  --timeout         timeout for the TCP socket
  --help            display usage information

```

# Example

```
~ ❯ tls-leak wikipedia.com                                                                                                                                   23:47:04
*.en-wp.com
*.en-wp.org
*.mediawiki.com
*.voyagewiki.com
*.voyagewiki.org
*.wiikipedia.com
*.wikibook.com
*.wikibooks.com
*.wikiepdia.com
*.wikiepdia.org
*.wikiipedia.org
*.wikijunior.com
*.wikijunior.net
*.wikijunior.org
*.wikipedia.com
en-wp.com
en-wp.org
mediawiki.com
voyagewiki.com
voyagewiki.org
wiikipedia.com
wikibook.com
wikibooks.com
wikiepdia.com
wikiepdia.org
wikiipedia.org
wikijunior.com
wikijunior.net
wikijunior.org
wikipedia.com
```
