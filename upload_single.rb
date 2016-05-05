##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
#require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Linux Upload a single file to a remote directory',
      'Description'   => %q{
        This module uploads a file from a local directory to a remote directory.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'leetyD and leetyW',
        ],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter']
    ))

    register_options(
      [
        OptString.new('localpath', [true, 'Path of local file to be uploaded.']),
	OptString.new('remotepath', [true, 'Remote path where the uploaded file will be placed.'])
      ], self.class)
  end

  def run
    upload_file("#{datastore['remotepath']}", "#{datastore['localpath']}")
    print_status("File upload successful from #{datastore['localpath']} to #{datastore['remotepath']}")
  end

end
