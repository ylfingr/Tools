#! /opt/puppetlabs/puppet/bin/ruby

require 'optparse'
require 'ostruct'

require 'fileutils'
require 'yaml'
require 'yaml/store'
require 'pp'

options = OpenStruct.new
options.key = nil
options.value = nil
options.files = Array.new

OptionParser.new do |opts|
  opts.on('-f', '--file FILE(s)', 'load (comma separated list of) FILE(s)') do |f|
    options.files = f.split(',')
  end
  opts.on('-k', '--key KEY', 'show only data of KEY') do |k|
    options.key = k
  end
  opts.on('-v', '--value VALUE', 'value') do |v|
    options.value = v
  end
end.parse!

if options.key.nil?
  puts "ERROR: key required"
  exit
end

options.files.sort.each do |yamlfile|
  begin
    store = YAML::Store.new yamlfile
    store.transaction do |doc|
      if options.value.nil?
        d = options.key.split(',').inject(doc, :[])
        unless d.nil?
          puts d.to_yaml
        else
          pp doc
        end
      else
        *key, last = options.key.split(',')
        begin
          key.inject(doc, :fetch)[last] = options.value
        rescue => e
          puts "failed to update #{options.key}: #{e}"
        end
      end

      store.commit
    end
  end
end
