#!/usr/bin/env ruby

require 'rubygems'
require 'xcodeproj'

project = Xcodeproj::Project.open("ObjectivePGP.xcodeproj")
target = project.targets.first

filenames = target.headers_build_phase.files.select do |pbx_header_file|
	pbx_header_file.settings["ATTRIBUTES"].include?("Public")
end.select do |file|
  file.display_name != "#{target.product_name}.h"
end.map do |file|
  file.display_name
end

File.open('ObjectivePGP/umbrella-tmp.h', 'w') do |f|
  filenames.each do |filename|
    f.puts "#import \"#{filename}\""
  end
end

system("jazzy --objc --umbrella-header ObjectivePGP/umbrella-tmp.h --module ObjectivePGP --framework-root ObjectivePGP")

File.delete('ObjectivePGP/umbrella-tmp.h')