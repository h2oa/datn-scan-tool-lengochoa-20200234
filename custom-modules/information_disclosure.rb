require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'information disclosure Scanner',
      'Description'    => %q{
        This module scans for multiple potential information disclosure to exploit
        information disclosure vulnerabilities by checking various common paths.
      },
      'Author'         => ['Hoa Le Ngoc'],
      'License'        => MSF_LICENSE,
      'References'     => [
        ['URL', 'https://cwe.mitre.org/data/definitions/419.html']
      ]
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'Base path to the web application', '/'])
      ])
  end

  def run
    admin_paths = [
      '.git/HEAD',
      'wp-config.php',
      'wp-content/debug.log',
      'source.zip',
      'robots.txt'
    ]

    admin_paths.each do |path|
      print_status("Checking #{path}")
      response = send_request_cgi(
        'method' => 'GET',
        'uri'    => normalize_uri(target_uri.path, path)
      )

      if response && response.code == 200 && response.body.size > 0
        print_good("Infomation disclosure at /#{path} - Status code: #{response.code}")
      else
        print_status("Nothing found at /#{path}")
      end
    end
  end
end
