#!/usr/bin/env ruby

$0 = $0

require 'optparse'
require 'socket'
require 'thread'

def debug(*args)
  info(*args) if $debug
end

def info(*args)
  STDERR.puts "#{$0}: " + sprintf(*args)
end

def die(*args)
  info(*args)
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
      last_error = Errno::ENOENT

      sock_path_list.each { |path|
        debug "Trying: %s", path
        begin
          return UNIXSocket.open(path)
        rescue => e
          debug "Failed"
          last_error = e
        end
      }

      raise e
    end
  end

  def sock_path_list
    list = []

    env = ENV['SSH_AUTH_SOCK']

    list.push(env) if env

    list.concat Dir.glob("/tmp/ssh-*/agent.*").select { |path|
      File.readable?(path) && path != env
    }.sort { |a, b|
      File.mtime(a) <=> File.mtime(b)
    }

    return list
  end

  def proxy(accept_sock)
    open { |client_sock|
      loop {
        r, w, e = IO.select([client_sock, accept_sock], nil, [client_sock, accept_sock], 1)

        if !e.empty?
          debug "Socket error"
          break
        end

        eof = false

        r.each { |s|
          buf, = s.recvfrom(4096)

          if buf.empty?
            eof = true
            next
          end

          debug "Data: %s", buf.inspect

          if s == accept_sock
            client_sock.send(buf, 0)
          else
            accept_sock.send(buf, 0)
          end
        }

        break if eof
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
        info "Fixing permissions: " + path;
        File.chmod(0700, dir)
      end
    rescue Errno::ENOENT => e
      Dir.mkdir(dir, 0700)
    end

    @listen_sock = UNIXServer.open(path)
  rescue => e
    raise RuntimeError, "Cannot create a server socket: #{e}"
  end

  def each
    loop {
      Thread.start(@listen_sock.accept) { |accept_sock|
        begin
          yield accept_sock
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
end

def cleanup
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

def daemon_main
  auth  = SSHAuth.new
  proxy = SSHAuthServer.new(sock_file())

  daemon()

  debug "PID: %d", Process.pid

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

    opt.on('-D', 'Turn on debug mode') { |v| $debug = v }
    opt.on('-k', 'Kill the agent') { |v| kill = v }

    opt.parse!(ARGV)

    if kill
      if pid = read_pid_file()
        begin
          Process.kill(:SIGTERM, pid)
        rescue => e
          info "#{e}"
        end
      else
        info "Cannot read pid file: %s" % pid_file()
      end

      cleanup

      exit
    end
  }

  daemon_main
rescue => e
  die "#{e}"
end

main()