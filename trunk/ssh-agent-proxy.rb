#!/usr/bin/env ruby
# -*- ruby -*-
#
# Copyright (c) 2006, 2008 Akinori MUSHA
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $Id$

$0 = $0

require 'optparse'
require 'socket'
require 'thread'
require 'shellwords'

def main
  setup

  OptionParser.new { |opt|
    kill = restart = false

    if shell = ENV['SHELL']
      $csh = shell.match(/csh$/)
    end

    opt.summary_width = 16
    opt.on('-a SOCK', 'Set the socket path (%d is replaced with UID)') { |v|
      $sock_file_template = v
    }
    opt.on('-c', 'Generate C-shell commands on stdout') { |v|
      $csh = v
    }
    opt.on('-d', 'Turn on debug mode') { |v|
      $debug = v
    }
    opt.on('-k', 'Kill the agent proxy, and remove the pid file and socket') { |v|
      kill = v
    }
    opt.on('-q', 'Suppress informational messages') { |v|
      $quiet = v
    }
    opt.on('-r', 'Restart the agent proxy') { |v|
      restart = v
    }
    opt.on('-s', 'Generate Bourne shell commands on stdout') { |v|
      $csh = !v
    }
    opt.on('-p FILE', 'Set the pid file path (%d is replaced with UID)') { |v|
      $pid_file_template = v
    }

    opt.parse!(ARGV)

    if kill || restart
      if pid = read_pid_file()
        begin
          Process.kill(:SIGTERM, pid)
        rescue => e
          die e.message
        end
      else
        die "Cannot read pid file: " + pid_file()
      end

      cleanup

      exit unless restart
    end
  }

  daemon_main
rescue => e
  die e.message
end

def daemon_main
  client = SSHAuthClient.new

  begin
    server = SSHAuthServer.new(sock_file())
  rescue Errno::EADDRINUSE => e
    print_info "Agent already running"

    print_env
    exit
  rescue => e
    $no_cleanup = true
    raise "Cannot create a server socket: #{e}"
  end

  print_env

  daemon()

  debug "PID: %d" % Process.pid

  create_pid_file

  server.each { |accept_sock|
    debug "Connected"

    client.proxy(accept_sock)

    debug "Disconnected"
  }
end

def daemon
  Process.daemon unless $debug
  File.umask(0)
end

def setup
  setup_global_variables
  setup_signal_handlers
end

def setup_global_variables
  $sock_file_template = "/tmp/ssh%d/agent.sock"
  $pid_file_template  = "/tmp/ssh%d/agent.pid"

  $debug              = false
  $csh                = false
  $no_cleanup         = false
  $quiet              = false
end

def setup_signal_handlers
  [:SIGINT, :SIGQUIT, :SIGTERM].each { |sig|
    trap(sig) do
      cleanup
      exit
    end
  }
end

def cleanup
  return if $no_cleanup

  [sock_file(), pid_file()].each { |path|
    dir, file = File.split(path)

    File.unlink(path) rescue nil
    Dir.rmdir(dir) rescue nil
  }
end

def sock_file
  return $sock_file_template % Process.uid
end

def pid_file
  return $pid_file_template % Process.uid
end

def create_pid_file
  path = pid_file()

  dir, file = File.split(path)

  if File.directory?(dir)
    File.chmod(0700, dir)
  else
    Dir.mkdir(dir, 0700)
  end

  File.open(path, "w") { |f|
    f.puts Process.pid
  }
end

def read_pid_file
  File.open(pid_file()) { |f|
    pid = f.gets.strip.to_i

    return pid
  }
rescue => e
  return nil
end

def debug(message)
  notice(message) if $debug
end

# Note that output to stdout may be passed to shell
def notice(message)
  STDERR.puts "#{$0}: #{message}"
end

def print_info(message)
  puts "echo " + "#{$0}: #{message}".shellescape + ";" unless $quiet
end

def print_env
  if $csh
    printf "setenv SSH_AUTH_SOCK %s;\n", sock_file().shellescape
  else
    printf "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", sock_file().shellescape
  end
end

def die(message)
  notice(message)

  cleanup

  exit 255
end

class SSHAuthClient
  class NoAgentError < StandardError; end

  def open(&block)
    if block
      sock = open()

      begin
        yield sock
      ensure
        sock.close
      end
    else
      last_error = nil

      sock_path_list.each { |path|
        debug "Trying: " + path
        begin
          stat = File.stat(path)

          if stat.socket? && stat.owned?
            return UNIXSocket.open(path)
          end
        rescue => last_error
          debug "Failed: #{e}"
          begin
            File.unlink(path)
            debug "Non-working socket removed"

            if (dir = File.dirname(path)) && File.owned?(dir)
              Dir.rmdir(dir)
              debug "Empty parent directory removed"
            end
          rescue
          end
        end
      }

      if last_error.nil?
        raise NoAgentError, 'No agent socket available'
      else
        raise last_error
      end
    end
  end

  def sock_path_list
    list = []

    # Socket opened by launchd(8) (for Mac OS X 10.5+)
    if File.executable?('/bin/launchctl')
      env = `/bin/launchctl getenv SSH_AUTH_SOCK 2>/dev/null`.chomp
      list << env unless env.empty?
    end

    # SSHKeychain (for Mac OS X)
    list << '/tmp/%d/SSHKeychain.socket' % Process.uid

    list.concat(Dir.glob("/tmp/ssh-*/agent.*").sort_by { |i|
      # ORDER BY mtime DESC
      -File.mtime(i).to_f
    })

    # never recurse itself
    list.delete(sock_file())

    list.delete_if { |path|
      begin
        stat = File.stat(path)

        !stat.socket? || !stat.owned?
      rescue
        true
      end
    }

    return list
  end

  SSH_AGENT_FAILURE = 5
  SSH_AGENT_SUCCESS = 6

  SSH_AGENTC_REQUEST_RSA_IDENTITIES = 1
  SSH2_AGENTC_REQUEST_IDENTITIES    = 11

  SSH_AGENT_RSA_IDENTITIES_ANSWER   = 2
  SSH2_AGENT_IDENTITIES_ANSWER      = 12

  def proxy(accept_sock)
    open { |client_sock|
      loop {
        reads, writes, errors = IO.select([client_sock, accept_sock],
                                          nil,
                                          [client_sock, accept_sock], 1)

        if !errors.nil?
          if !errors.empty?
            debug "Socket error"
            break
          end
        end

        next if reads.nil?

        eof = false

        reads.each { |s|
          buf = s.recv(4096)

          if buf.empty?
            eof = true
            next
          end

          if s.equal?(accept_sock)
            debug "Request from client: " + buf.inspect
            client_sock.send(buf, 0)
          else
            debug "Response from server: " + buf.inspect
            accept_sock.send(buf, 0)
          end
        }

        break if eof
      }
    }
  rescue NoAgentError
    loop {
      reads, writes, errors = IO.select([accept_sock],
                                        nil,
                                        [accept_sock], 1)

      if !errors.nil?
        if !errors.empty?
          debug "Socket error"
          break
        end
      end

      next if reads.nil?

      req_len_packed = accept_sock.read(4) or break

      req_len = req_len_packed.unpack('N').first
      req_message = accept_sock.read(req_len)
      req = [req_len, req_message].pack('Na*')
      req_type, req_data = req_message.unpack('Ca*')

      debug "Request from client: " + req.inspect

      case req_type
      when SSH_AGENTC_REQUEST_RSA_IDENTITIES
        res_message = [SSH_AGENT_RSA_IDENTITIES_ANSWER, 0].pack('CN')
      when SSH2_AGENTC_REQUEST_IDENTITIES
        res_message = [SSH2_AGENT_IDENTITIES_ANSWER, 0].pack('CN')
      else
        res_message = [SSH_AGENT_FAILURE].pack('C')
      end

      res = [res_message.size, res_message].pack('Na*')

      debug "Response: " + res.inspect
      accept_sock.send(res, 0)
    }
  end
end

class SSHAuthServer
  def initialize(path)
    dir, file = File.split(path)

    begin
      stat = File.stat(dir)

      if stat.directory? && (stat.mode & 0077) != 0
        notice "Fixing permissions: " + path
        File.chmod(0700, dir)
      end
    rescue Errno::ENOENT => e
      Dir.mkdir(dir, 0700)
    end

    @listen_sock = UNIXServer.open(path)
  rescue Errno::EADDRINUSE => e
    begin
      # test if the existing socket is working
      sock = UNIXSocket.open(path)
      sock.close
    rescue => e
      notice "Removing a dead socket in the way"
      File.unlink(path)

      # The socket having been unlinked, EADDRINUSE shall no longer be raised.
      @listen_sock = UNIXServer.open(path)
      return
    end

    raise Errno::EADDRINUSE
  end

  def each
    loop {
      Thread.start(@listen_sock.accept) { |accept_sock|
        begin
          yield accept_sock
        rescue => e
          debug e.message
          raise e
        ensure
          accept_sock.close
        end
      }
    }
  end
end

class String
  def shellescape
    # An empty argument will be skipped, so return empty quotes.
    return "''" if empty?

    str = dup

    # Process as a single byte sequence because not all shell
    # implementations are multibyte aware.
    str.gsub!(/([^A-Za-z0-9_\-.,:\/@\n])/n, "\\\\\\1")

    # A LF cannot be escaped with a backslash because a backslash + LF
    # combo is regarded as line continuation and simply ignored.
    str.gsub!(/\n/, "'\n'")

    return str
  end unless method_defined?(:shellescape)
end

module Process
  class << self
    def daemon(nochdir = nil, noclose = nil)
      fork and exit!(0)
      fork and exit!(0)

      Process.setsid
      Dir.chdir("/") unless nochdir

      unless noclose
        STDIN.reopen("/dev/null")
        STDOUT.reopen("/dev/null", "w")
        STDERR.reopen("/dev/null", "w")
      end
    end unless method_defined?(:daemon)
  end
end

main()
