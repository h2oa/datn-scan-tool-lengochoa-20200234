require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Apache Solr Endpoint Exposure Scanner',
      'Description'    => %q{
        This module scans for Apache Solr instances that have exposed and potentially vulnerable endpoints.
        It specifically looks for the presence of management interfaces or APIs that are accessible without authentication.
      },
      'Author'         => [
        'Hoa Le Ngoc'
      ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://www.acunetix.com/vulnerabilities/web/apache-solr-endpoint/'],
        ]
    ))

    register_options([
      Opt::RPORT(8983),
      OptString.new('TARGETURI', [true, 'Path to Apache Solr', '/solr/'])
    ])
  end

  def run_host(ip)
    paths = [
      'admin/info/system',
      'admin/cores',
      'admin/collections',
      # Add other endpoints that you need to check
    ]

    paths.each do |path|
      uri = normalize_uri(target_uri.path, path)
      print_status("Checking #{ip}:#{rport}#{uri}")
      res = send_request_cgi({
        'uri'    => uri,
        'method' => 'GET'
      })

      unless res
        print_error("No response from #{ip}:#{rport}#{uri}")
        next
      end

      if res.code == 200
        print_good("Found exposed Solr endpoint at #{ip}:#{rport}#{uri}")
        print_line("===Response start===\n#{response.headers}\n#{response.body}\n===Response end===")
        report_vuln({
          host: ip,
          port: rport,
          proto: 'tcp',
          name: 'Exposed Apache Solr Endpoint',
          info: "Exposed endpoint at #{uri}",
          refs: references,
        })
      else
        print_status("No exposed endpoint found at #{ip}:#{rport}#{uri}")
      end
    end
  end
end
