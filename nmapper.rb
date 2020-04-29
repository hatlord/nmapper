#!/usr/bin/env ruby

#Parses NMAP Scans to report table format

require 'nokogiri'
require 'caxlsx'

@nmap_files = Dir.glob(ARGV[0] + '/*.xml')

@scan_array = []

def parse
  @nmap_files.each do |file|
    nmap = Nokogiri::XML(File.read(file))
    start_time  = nmap.xpath('./nmaprun/@startstr').text
    end_time    = nmap.xpath('./nmaprun/runstats/finished/@timestr').text
    elapsed     = Time.at(nmap.xpath('./nmaprun/runstats/finished/@elapsed').text.to_i).utc.strftime("%H:%M:%S")
    hosts_up    = nmap.xpath('./nmaprun/runstats/hosts/@up').text
    hosts_down  = nmap.xpath('./nmaprun/runstats/hosts/@down').text
    hosts_total = nmap.xpath('./nmaprun/runstats/hosts/@total').text
    args        = nmap.xpath('./nmaprun/@args').text

    nmap.xpath('./nmaprun/host').each do |ports|
      hosts = {}

        hosts[:addr]      = ports.xpath('./address[1]/@addr').text
        hosts[:mac]       = ports.xpath('./address[2]/@addr').text
        hosts[:vendor]    = ports.xpath('./address[2]/@vendor').text
        hosts[:os]        = ports.xpath('./os/osmatch/@name').map(&:text).join("\r")
        puts "Parsing: #{hosts[:addr]}"

          ports.xpath('./ports/port').each do |srvc|
            if srvc.xpath('./state/@state').text == 'open'
              hosts[:file]      = File.basename(file, '.*')
              hosts[:args]      = args
              hosts[:start]     = start_time
              hosts[:end]       = end_time
              hosts[:time]      = elapsed
              hosts[:up]        = hosts_up
              hosts[:down]      = hosts_down
              hosts[:total]     = hosts_total
              hosts[:proto]     = srvc.xpath('./@protocol').text
              hosts[:port]      = srvc.xpath('./@portid').text
              hosts[:service]   = srvc.xpath('./service/@name').text
              hosts[:reason]    = srvc.xpath('./state/@reason').text
              hosts[:product]   = srvc.xpath('./service/@product').text
              hosts[:version]   = srvc.xpath('./service/@version').text
              hosts[:extra]     = srvc.xpath('./service/@extrainfo').text
              hosts[:scriptid]  = srvc.xpath('./script/@id').text
              hosts[:scriptout] = srvc.xpath('./script/@output').text
              hosts[:protop]    = hosts[:proto].upcase + "/" + hosts[:port]
              hosts[:combo]     = hosts[:product] + " " + hosts[:version] + " " + hosts[:extra]

              if hosts[:combo].strip.length == 0
                hosts[:combo] = "unknown"
              end

              if hosts[:os].empty?
                hosts[:os] = "Unable to Fingerprint"
              end

              if hosts[:os].include?('Linux 2.')
                hosts[:os] = "Linux Kernel 2.x"
              elsif hosts[:os].include?('Linux 3.')
                hosts[:os] = "Linux Kernel 3.x"
              end

            @scan_array << hosts.dup
        end
      end
    end
  end
end

def group_by_ip
  scanarray = []
  grouped = @scan_array.group_by {|e| e[:addr]}
  grouped.each do |k, v|
    scandata = {}
    scandata[:ip] = k
    scandata[:ports] = []
    v.each do |value|
      scandata[:ports] << value[:protop]
    end
    scanarray << scandata
  end
  scanarray
end

def create_excel_file
  @excel_file = "#{Dir.home}/Documents/nmapper_out/nmapper_#{Time.now.strftime("%d%b%Y_%H%M%S")}.xlsx"
  @p = Axlsx::Package.new
  @wb = @p.workbook
end

def create_excel_data(headers, rows, sheetname)
  @wb.add_worksheet(:name => sheetname) do |sheet|
    sheet.add_row(headers)
    rows.each do |row|
      sheet.add_row row
    end
  end
  @p.serialize @excel_file
end

def create_directory
  Dir.mkdir("#{Dir.home}/Documents/nmapper_out/") unless File.exists?("#{Dir.home}/Documents/nmapper_out/")
end

def create_basic_open_ports_list
  rows      = []
  headers   = ['NMAP File', 'Command', 'Scan Start', 'Scan End', 'Scan Time', 'Hosts Up', 'Hosts Down', 'Total Hosts', 'IP', 'Responding MAC Addr', 'Responding Mac Addr Vendor', 'OS', 'Port', 'Service Version', 'ScriptID', 'Script Output', 'Reason for Open Port']
  sheetname = 'Open Ports'
  @scan_array.each do |result|
    rows << [result[:file], result[:args], result[:start], result[:end], result[:time], result[:up], result[:down], result[:total], result[:addr], result[:mac], result[:vendor], result[:os], result[:protop], result[:combo], result[:scriptid], result[:scriptout], result[:reason]]
  end
  create_excel_data(headers, rows, sheetname)
end

def condensed_open_ports
  rows      = []
  headers   = ['IP', 'Ports', 'Port Count']
  sheetname = 'CondensedPorts'
  group_by_ip.each do |inner|
    rows << [inner[:ip], inner[:ports].join(", "), inner[:ports].length]
  end
  create_excel_data(headers, rows.sort_by { |e| e[2].to_i}.reverse, sheetname)
end

def group_by_port
  #should come back and consolidate this and group_by_ips ideally
  array_of_rows = []
  grouped_by_port = @scan_array.group_by {|e| e[:protop]}
  grouped_by_port.each do |k, v|
    rows = {}
    rows[:addrs] = []
    rows[:port] = k
    v.each do |value|
      rows[:addrs] << value[:addr]
    end
    array_of_rows << rows
  end
  array_of_rows
end

def grouped_by_port_excel
  #need to condense this and condensed_open_ports
  rows      = []
  headers   = ['Port', 'IP Addresses', 'IP Count']
  sheetname = 'GroupedByPort'
  group_by_port.each do |inner|
    rows << [inner[:port], inner[:addrs].join(", "), inner[:addrs].length]
  end
  create_excel_data(headers, rows.sort_by { |e| e[2].to_i}.reverse, sheetname)
end

def terminal_out
  puts "Data written to #{@excel_file}"
end

parse
create_directory
create_excel_file
create_basic_open_ports_list
condensed_open_ports
grouped_by_port_excel
# group_by_port
terminal_out
