##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'set'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
                      'Name'        => 'CORS misconfiguration scanner',
                      'Description' => %q{ This module sdcans HTTP Headers related to Cross Origin Resource Sharing policy returned by the scanned host. },
                      'Author'      =>
                          [
                              'Andrei Hincu <andrei@hincu.io>'
                          ],
                      'References'  =>
                          [
                              ['URL', 'https://tools.ietf.org/html/rfc6454'],
                              ['URL', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
                              ['URL', 'https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties'],
                              ['URL', 'https://www.corben.io/advanced-cors-techniques/'],
                              ['URL', 'https://www.youtube.com/watch?v=qHhhg1CEJfY'],
                              ['URL', 'https://www.youtube.com/watch?v=22CKQ_xed9s']
                          ],
                      'License'     => MSF_LICENSE
          ))

    register_options([
                         OptEnum.new('HTTP_METHOD', [ true, 'HTTP Request Method', 'OPTIONS', ['OPTIONS', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE'] ]),
                         OptString.new('PATH', [ true, 'Vulnerable path. Ex: /foo/resource/add', '/']),
                         OptBool.new('SSL', [ true, 'Use HTTPS', true]),
                         OptInt.new('RPORT', [ true, 'The target port (TCP)', 443]),
                         OptString.new('VHOST', [ true, 'HTTP server virtual host (eg. example.com)'])

                     ])
  end


  # Downloads the suffix list from https://publicsuffix.org/list/public_suffix_list.dat as a simple text.
  #
  # @return [String] The suffix list as a string, or nil if it couldn't download it.
  def get_public_suffix_list()
    uri = URI('https://publicsuffix.org/list/public_suffix_list.dat')
    response = Net::HTTP.get_response(uri)

    if response.is_a? Net::HTTPSuccess
      return response.body
    else
      return nil
    end
  end

  # Converts the object into textual markup given a specific format.
  #
  # @return [Hash] Hash of sets per etld
  def get_domain_name_suffixes()

    text = get_public_suffix_list()

    suffixes = {}
    lines = text.lines

    lines.each do |l|
      l = l.strip
      next if (l.start_with?("//") or l == "")

      if l[0] == "*"
        # Any hostname matches wildcard
        etld = l[2..]
        if !suffixes.has_key? etld
          suffixes[etld] = Set.new
        end
        suffixes[etld].add("*")
      elsif l[0] == "!"
        # Exceptions to the wildcard rule
        doms = l.split(".")
        etld = doms[1..].join(".")
        if !suffixes.has_key? etld
          suffixes[etld] = Set.new
        end
        suffixes[etld].add(doms[0])
      else
        if !suffixes.has_key? l
          suffixes[l] = Set.new
        end

      end
    end

    return suffixes
  end

  # Returns the Effective Top Level Domain for a given domain name and given suffixes list.
  # @param domain [String] The domain name
  # @return [String] the ETLD of the domain
  def get_etld(domain)
    suffixes = get_domain_name_suffixes()

    dlabels = domain.strip().split(".")

    etld = nil

    for i in 0...dlabels.length
      etld = dlabels[i..].join(".")
      break if suffixes.has_key? etld
      etld = nil
    end

    return nil if etld == nil

    if ((i >= 1) and (suffixes[etld].include? "*") and !(suffixes[etld].include?(("!"+dlabels[i-1]))))
      etld = dlabels[i-1] + "." + etld
    end

    return etld
  end


  # Returns the Effective Top Level Domain Plus One for a given domain name and given suffixes list.
  # @param domain [String] The domain name
  # @return [String] the ETLDP1 of the domain
  def get_etld_plus_one(domain)
    etld = get_etld(domain)

    # if there is no official etld, then it can be some intranet alias so we'll leave it as is
    # also, if the etld is the actual domain name (like edgestack.me)
    return domain if etld == nil || etld == domain

    # if the subdomains are something like sd1.sd2.sd3.sd4.etld then we want sd4
    # if it's subdomain.etld, then we take subdomain
    # in other words, we always take the last element
    subdoms = domain[0...domain.index(etld)-1].split(".")
    return "#{subdoms[-1]}.#{etld}"
  end

  def get_cors_headers(response)
    headers_origin = response.headers.select{ |key, value| key =~ /Access-Control-Allow/}

    unless headers_origin
      return nil
    end

    return headers_origin.map().to_h
  end

  def execute_request(origin)
    uri = normalize_uri(target_uri.path)

    vprint_status "#{peer}: Testing origin \"#{origin}\"..."

    opts = {
        'method'  => datastore['HTTP_METHOD'],
        'uri'     => uri,
        'headers' =>
            {
                'Origin' => origin,
            },
        'vhost' => datastore['VHOST']
    }

    res = send_request_cgi(opts)

    if res && res.redirect? && res.redirection
      location = res.redirection.to_s
      vprint_status("#{peer}: Following redirect to #{location}")

      opts['vhost'] = res.redirection.host
      res = send_request_cgi(opts)
    end

    return res

  end

  def generate_evil_origins(vhost)
    origins = []
    domain_elements = vhost.split('.')

    # add all origins
    origins.push "*"

    # add null origin
    origins.push "null"

    # add reflect origin
    origins.push "https://evil.com"

    # add any subdomain origin
    origins.push "https://evil.#{vhost}"

    # add prefix origin match
    origins.push "https://#{vhost}.evil.com"

    # add a variation of effective domain plus one (eg. victim.com becomes wvictim.com and ictim.com)
    etldp1 = get_etld_plus_one(vhost)
    if etldp1 != nil
      origins.push "https://#{etldp1[1..]}" # try removing the first letter of etldp1
      origins.push "https://w#{etldp1}" # try prepending a letter to the etldp1 (preferably "w", since it commes from www)
      origins.push "https://www#{etldp1}" # try prepending "www" to the etldp1
      origins.push "https://wwww#{etldp1}" #try prepending "wwww" to the etldp1 (the 4th w is to replace an unescaped pre-dot)
    end

    # add unescaped dot origin (the last dot is often forgotten from escaping)
    origins.push "https://#{domain_elements[0..-2].join('.')}w#{domain_elements[-1]}"

    # add non TLS origin of the same domain
    origins.push "http://#{vhost}"

    # trying other characters (only Safari has this problemb, it will not work in Chrome or Firefox)
    # as described in this article: https://www.corben.io/advanced-cors-techniques
    specialCharacters = %w[, & ' " ; ! $ ^ * ( ) + = ` ~ - _ | { } %]

    specialCharacters.each do |c|
      origins.push "https://#{vhost}#{c}.evil.com"
    end

    return origins
  end

  def run_host(ip)
    origins = generate_evil_origins(vhost)

    origins.each do |origin|
      res = execute_request(origin)

      unless res
        vprint_error("#{peer}: connection timed out for origin \"#{origin}\" ")
        next
      end

      aca_headers = get_cors_headers(res)


      #  Rejecting a CORS request means:
      # 1) Responding with an Access-Control-Allow-Origin header that doesn’t match the Origin header or is not "*"
      # 2) Removing the Access-Control-Allow-Origin header entirely
      # 3) A third case that's tricky. If there is a CORS request without pre-flight (GET/POST/HEAD),
      # especially in the case of a POST one that involves some sort of modification on the server side,
      # not having the ACAO header is not enough. The request can still be successful on the server side.
      # When the browser rejects the CORS request, it doesn’t send the response to the client.
      # But the actual HTTP request is still made to the server, and the server still sends
      # back an HTTP response, which means that the CORS request might have been able to generate
      # some operations on the backend, especially in the case of POST requests




      # # if no Access-Control-Allow-* headers are present in the response, then no CORS, so safe
      # unless aca_headers
      #   vprint_good("#{peer}: Target website is safe against CORS requests from origin \"#{origin}\"!")
      #   next
      # end

      acao_header = aca_headers['Access-Control-Allow-Origin']


      # if no Access-Control-Allow-* headers are present in the response, then no CORS are allowed, so target is safe
      unless aca_headers
        vprint_good("#{peer}: Target website is safe against CORS requests from origin \"#{origin}\"!")
        next
      end

      acao_header = aca_headers['Access-Control-Allow-Origin']

      # normally, if acao header is no present in the request, then CORS is secure
      # also, if the acao header is not equal to the one queried, then it's ok as well
      if (acao_header == nil) || (acao_header != origin)
        vprint_good("#{peer}: Target website is safe against CORS requests from origin \"#{origin}\"!")
      else
        print_error("#{peer}: Target website is vulnerable to CORS requests from origin \"#{origin}\"!")
        report_web_vuln(
            :host	=> ip,
            :port	=> rport,
            :vhost  => vhost,
            :ssl    => ssl,
            :path	=> datastore['PATH'],
            :method => datastore['HTTP_METHOD'],
            :pname  => "",
            :proof  => "Insecure CORS request",
            :risk   => 2,
            :confidence   => 100,
            :category     => 'Broken Access Control',
            :description  => "Insecure CORS request on url https://#{datastore['VHOST']}/#{datastore['PATH']} from origin #{origin} using method #{datastore['HTTP_METHOD']}",
            :name   => 'Insecure CORS'
        )
      end
    end
  end
end
# docker run --rm -it -v ${path}:/home/msf/.msf4 --name metasploit metasploitframework/metasploit-framework /usr/src/metasploit-framework/msfconsole -q -x 'use scanner/http/cors;set SSL true;set RPORT 443;set RHOSTS sohu.com;set VHOST sohu.com;set VERBOSE true;run;exit'