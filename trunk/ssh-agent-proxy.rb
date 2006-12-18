#!/usr/bin/env ruby
# -*- ruby -*-
#
# Copyright (c) 2006 Akinori MUSHA
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

def shellescape(str)
  return str.gsub(/([^A-Za-z0-9_\-.,:\/@])/on, "\\\\\\1")
end

def debug(message)
  notice(message) if $debug
end

# Note that output to stdout may be passed to shell
def notice(message)
  STDERR.puts "#{$0}: #{message}"
end

def info(message)
  puts "echo " + shellescape("#{$0}: #{message}") + ";" unless $quiet
end

def die(message)
  notice(message)

  cleanup

  exit 255
end

def daemon
  return if $debug

  fork and exit!(0)

  Process::setsid

  fork and exit!(0)

  Dir::chdir("/")
  File::umask(0)

  STDIN.reopen("/dev/null")
  STDOUT.reopen("/dev/null", "w")
  STDERR.reopen("/dev/null", "w")
end

class SSHAuth
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
          return UNIXSocket.open(path)
        rescue => e
          debug "Failed"
          File.chmod(0200, path) rescue nil
          last_error = e
        end
      }

      if last_error.nil?
        raise 'No agent socket available'
      else
        raise last_error
      end
    end
  end

  def sock_path_list
    list = []

    # SSHKeychain (Mac OS X)
    list << '/tmp/%d/SSHKeychain.socket' % Process.uid

    list.concat(Dir.glob("/tmp/ssh-*/agent.*").sort_by { |i|
      # ORDER BY mtime DESC
      -File.mtime(i).to_f
    })

    if env = ENV['SSH_AUTH_SOCK']
      # use the env as the first candidate
      list.delete(env)
      list.unshift(env)
    end

    # never recurse itself
    list.delete(sock_file())

    return list
  end

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

        eof = false

        if !reads.nil?
          reads.each { |s|
            buf, = s.recvfrom(4096)

            if buf.empty?
              eof = true
              next
            end

            debug "Data: " + buf.inspect

            if s.equal?(accept_sock)
              client_sock.send(buf, 0)
            else
              accept_sock.send(buf, 0)
            end
          }

          break if eof
        end
      }
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

def cleanup
  return if $no_cleanup

  [sock_file(), pid_file()].each { |path|
    dir, file = File.split(path)

    File.unlink(path) rescue nil
    Dir.rmdir(dir) rescue nil
  }
end

def setup_signal_handlers
  [:SIGINT, :SIGQUIT, :SIGTERM].each { |sig|
    trap(sig) do
      cleanup
      exit
    end
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

def print_env
  if $csh
    printf "setenv SSH_AUTH_SOCK %s;\n", shellescape(sock_file())
  else
    printf "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", shellescape(sock_file())
  end
end

def daemon_main
  auth = SSHAuth.new

  begin
    proxy = SSHAuthServer.new(sock_file())
  rescue Errno::EADDRINUSE => e
    info "Agent already running"

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

  proxy.each { |accept_sock|
    debug "Connected"

    auth.proxy(accept_sock)

    debug "Disconnected"
  }
end

def main
  setup

  OptionParser.new { |opt|
    kill = false

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
    opt.on('-s', 'Generate Bourne shell commands on stdout') { |v|
      $csh = !v
    }
    opt.on('-p FILE', 'Set the pid file path (%d is replaced with UID)') { |v|
      $pid_file_template = v
    }

    opt.parse!(ARGV)

    if kill
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

      exit
    end
  }

  daemon_main
rescue => e
  die e.message
end

main()
