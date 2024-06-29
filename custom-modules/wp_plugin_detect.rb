require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Wordpress plugins Scanner',
      'Description'    => %q{
        This module scans for wordpress plugins based on a list of slugs in an external file.
      },
      'Author'         => ['Hoa Le Ngoc'],
      'License'        => MSF_LICENSE,
      'References'     => [
        ['URL', 'https://wpscan.com/']
      ]
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'Base path to the web application', '/']),
        OptString.new('PLUGINSLUGLIST', [true, 'Path to the file containing plugin slugs', 'plugin_slugs.txt'])
      ])
  end

  def run
    unless File.file?(datastore['PLUGINSLUGLIST'])
      print_error("Plugin slug list file does not exist.")
      return
    end

    file = File.new(datastore['PLUGINSLUGLIST'], "r")
    plugin_slugs = file.read.split

    plugin_slugs.each do |slug|
      readme_path = "/wp-content/plugins/#{slug}/readme.txt"
      print_status("Checking plugin at #{readme_path}")
      response = send_request_cgi(
        'method' => 'GET',
        'uri'    => normalize_uri(target_uri.path, readme_path)
      )

      if response && response.code == 200
        print_good("Found plugin #{slug} - Status code: #{response.code}")
      else
        print_status("No plugin found at #{readme_path}")
      end
    end

    file.close
  end
end
