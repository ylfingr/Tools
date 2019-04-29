#! /opt/puppetlabs/puppet/bin/ruby

require 'optparse'
require 'ostruct'
require 'fileutils'
require 'yaml'

class Symbol
    def call(*args, &block)
        ->(caller, *rest) { caller.send(self, *rest, *args, &block) }
    end
end

$FSTAB = '/tmp/fstab'
options = OpenStruct.new
options.fstab = $FSTAB
options.newfstab = nil
options.vfstype = 'nfs'
options.ohosts = Array.new
options.nhosts = Array.new

OptionParser.new do |opts|
    opts.on('-f', '--fstab PATH', 'path to fstab') do |fstab|
        options.fstab = fstab
    end
    opts.on('-t', '--fstype FS', 'filesystem type') do |fs|
        options.vfstype = fs
    end
    opts.on('-h', '--old-hosts HOST', 'comma-separated list of remote netfs hosts to consider') do |host|
        options.ohosts = host.split(',')
    end
    opts.on('-H', '--new-hosts HOST', 'comma-separated list of remote netfs hosts to consider') do |host|
        options.nhosts = host.split(',')
    end
end.parse!

$FSTAB = options.fstab

begin
	fstab = File.readlines($FSTAB).map(&:chomp)
rescue => e
	STDERR.printf("Failed to read file '%s': %s\n", $FSTAB, e)
	exit -1
end

mounts = Proc.new do |line|
	head, *tail = line.split(/\s+/)

	# skip empty lines
	next if head.nil? or head.empty?

	# skip comments
	next if head =~ /^#/

	fs_spec, fs_file, fs_vfstype, fs_mntopts, fs_freq, fs_pass = line.split(/\s+/)
	rhost, rpath = fs_spec.split(':')
	rhost, *domain = rhost.split('.')

	fs_vfstype == options.vfstype and ($HOSTS.empty?  or $HOSTS.include? rhost)
end

_fstab = Hash.new
_fstab_keys = [:fs_spec, :fs_file, :fs_vfstype, :fs_mntopts, :fs_freq, :fs_pass]

$HOSTS = options.ohosts
_fstab[:ohosts] = Array.new
fstab.select(&mounts).each do |mount|
	rpath = mount.split(/\s+/)[0].split(':')[1]
	_fstab[:ohosts] << {:fs_rpath => rpath}.merge( _fstab_keys.zip(mount.split(/\s+/)).to_h )
end

$HOSTS = options.nhosts
_fstab[:nhosts] = Array.new
fstab.select(&mounts).each do |mount|
	rpath = mount.split(/\s+/)[0].split(':')[1]
	_fstab[:nhosts] << {:fs_rpath => rpath}.merge( _fstab_keys.zip(mount.split(/\s+/)).to_h )
end

diff = Hash.new
diff[:new] = _fstab[:nhosts].map {|x| x[:fs_rpath]} - _fstab[:ohosts].map {|x| x[:fs_rpath]}
diff[:old] = _fstab[:ohosts].map {|x| x[:fs_rpath]} - _fstab[:nhosts].map {|x| x[:fs_rpath]}

idiff = Hash.new
idiff[:new] = diff[:new].length
idiff[:old] = diff[:old].length

if 0 < idiff.values.inject(:+)
	diff.each do |where, mounts|
		unless mounts.empty?
			puts "#{where}:"
			mounts.each do |mount|
				puts "    #{mount}"
			end
		end
	end
	exit 1
end
