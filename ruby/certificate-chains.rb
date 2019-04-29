#! /usr/bin/env ruby

gem 'openssl'
require 'openssl'
require 'optparse'
require 'ostruct'
require 'pathname'
require 'digest'

class ExtensionNotFound < StandardError
end

def abspath(root, *paths)
  File.join(File.split(File.expand_path(File.join(root, *paths))))
end

def load_certificate(crtfile)
  crtdata = File.read crtfile
  begin
    return OpenSSL::X509::Certificate.new crtdata
  rescue => e
    puts "Failed to load #{crtfile}: #{e}"
    return nil
  end
end

def load_certificates(crtpath = '.')
  certificates = Hash.new
  certificates_path = Pathname.new(crtpath)

  certificates_path.each_entry do |filename|
    next unless ['.crt', '.pem', '.der'].include?(File.extname(filename))

    fullpath = abspath(crtpath, filename)
    loaded = load_certificate(fullpath)
    unless loaded.nil?
      certificates[fullpath] = loaded
    end
  end
  return certificates
end

def x509_extensions(x509)
  xts = Hash.new
  x509.extensions.each do |e|
    xts[e.oid()] = e.value()
  end
  return xts
end

def authority_key_identifier extensions
  id = extensions['authorityKeyIdentifier']
  if id
    head, *tail = id.strip.split(':')
    return tail.join(':')
  else
    raise ExtensionNotFound, 'extension "authorityKeyIdentifier" not found'
  end
end

def subject_key_identifier extensions
  id = extensions['subjectKeyIdentifier']
  if id
    return id.strip
  else
    raise ExtensionNotFound, 'extension "subjectKeyIdentifier" not found'
  end
end

def issuer(x509)
  x509.issuer.to_s
end
def subject(x509)
  x509.subject.to_s
end
def subject_hash(x509, base = 16)
  x509.subject.hash.to_s(base)
end

def fingerprint(x509, digest = :sha256)
  der = x509.to_der

  digests = [:md5, :rmd160, :sha1, :sha256, :sha384, :sha512]

  def __fingerprint(der, digest = :sha256)
    mod = Object.const_get(:Digest).const_get(digest.to_s.upcase.to_sym)
    mod.hexdigest(der).upcase.chars.each_slice(2).map(&:join).join(':')
  end

  hdigests = Hash.new
  if digest == :all
    digests.each do |_digest|
      k = [_digest.to_s.upcase, 'fingerprint'].join(' ')
      hdigests[k] = __fingerprint(der, _digest)
    end
  elsif digests.include?(digest)
    k = [digest.to_s.upcase, 'fingerprint'].join(' ')
    hdigests[k] = __fingerprint(der, digest)
  end

  hdigests
end

def info(x509, extensions = Hash.new)
  crtinfo = {
    :issuer        => issuer(x509),
    :subject       => subject(x509),
    :subject_hash  => subject_hash(x509),
    :notbefore     => x509.not_before,
    :notafter      => x509.not_after,
    :serial        => x509.serial,
  }

  if san = extensions['subjectAltName']
    crtinfo[:san] = san
  end
  crtinfo.merge(fingerprint(x509, :all))
end

def chain_new(crtfile, certificates, crtpath = '.')
  chained = []

  x509  = certificates[crtfile]
  hash  = subject_hash(x509)
  index = 0

  sslpath = Pathname.new(crtpath)
  hash_index = [hash, index].join('.')

  hi_link = File.join(sslpath, hash_index)

  if File.exist?(hi_link) and File.symlink?(hi_link)
  end
end

def chain(crtfile, certificates, crtpath = '.')
  chained = []

  x509 = certificates[crtfile]
  return false, chained if x509.nil?

  extensions = x509_extensions(x509)
  begin
    subjectKeyId   = subject_key_identifier(extensions)
  rescue ExtensionNotFound => e
    puts "#{crtfile}: #{e}"
    return false, chained
  end

  begin
    authorityKeyId = authority_key_identifier(extensions)
  rescue ExtensionNotFound => e
    puts "#{crtfile}: #{e}"
    authorityKeyId = subjectKeyId
  end

  crtinfo = info(x509, extensions)

  chained << {crtfile => crtinfo}
  certificates.each do |_crtfile, _x509|
    next if _crtfile == crtfile

    _extensions = x509_extensions(_x509)
    begin
      _subjectKeyId = subject_key_identifier(_extensions)
    rescue ExtensionNotFound => e
      next
    end

    begin
      _authorityKeyId = authority_key_identifier(_extensions)
    rescue ExtensionNotFound => e
      _authorityKeyId = _subjectKeyId
    end

    crtinfo = info(_x509, _extensions)
    if authorityKeyId == _subjectKeyId
      authorityKeyId = _authorityKeyId
      chained << {_crtfile => crtinfo}

      if _authorityKeyId == _subjectKeyId
        return true, chained
      end
    end
  end
  puts("!!! WARNING: Incomplete chain !!!")
  return false, chained
end

def dump_certificate(outfile, complete, chained)
  unless outfile
    fdout = $stdout.dup
  else
    outfile_abspath = abspath(outfile)
    fdout = File.open(outfile_abspath, 'a')
  end

  chained.each do |crtinfo|
    crtinfo.each do |crt, _info|
      s_crtinfo = _info.map do |k, v|
        "# %24{k}: %{v}" % {k: k, v: v}
      end
      fdout.puts "# #{File.basename(crt)}"
      fdout.puts s_crtinfo
      fdout.puts File.read(crt)
    end
  end
  fdout.close

  unless complete
    puts("!!! WARNING: Incomplete chain !!!")
  end
end


if 0 == caller.length
  options = OpenStruct.new
  options.sslpath = 'sslcerts'
  options.sslfile = nil
  options.outfile = nil
  options.stdout  = false

  OptionParser.new do |option|
    option.on('-p', '--sslpath SSLPATH', 'directory of certificates')  do |p|
      options.sslpath = File.expand_path(p)
    end
    option.on('-i', '--infile CRTFILE', 'certificate to build the chain to') do |f|
      options.sslfile = f
    end
    option.on('-o', '--outfile CHAINFILE', 'file to write the chain to') do |f|
      options.outfile = f
    end
    option.on('-P', '--chainpath CHAINPATH', 'chained certificates path') do |p|
      options.chainpath = File.expand_path(p)
    end
    option.on('-s', '--stdout', 'write to STDOUT') do
      options.stdout  = true
      options.outfile = nil
    end
  end.parse!

  sslpath = options.sslpath
  unless sslpath
    raise OptionParser::MissingArgument, "'sslpath' is required"
  end

  certificates = load_certificates(crtpath = sslpath)
  outfile = options.outfile

  sslfile = options.sslfile
  if sslfile
    sslfile_abspath = abspath(sslpath, sslfile)
    complete, chained = chain(sslfile_abspath, certificates, crtpath = sslpath)
    dump_certificate(outfile, complete, chained)
  else
    chainpath = options.chainpath
    unless chainpath
      raise OptionError::MissingArgument, "'chainpath' is required"
    end

    root   = Pathname.new(sslpath)
    chains = Pathname.new(chainpath)

    certificates.each do |crt, _info|
      complete, chained = chain(crt, certificates, crtpath = sslpath)
      outfile = options.stdout or File.join(chains, File.basename(crt))
      dump_certificate(outfile, complete, chained)
    end
  end
end
