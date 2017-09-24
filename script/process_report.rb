require "csv"
require "pry"

filename = ARGV[0]
destination_filename = ARGV[1]
csv_hash = {}

CSV.foreach(filename) do |row|
  next if row == ["Request URL", "Request Method", "Request Headers", "Request body", "Request Parameters", "Event label", "Event type"]
  key = row[0..4].join(" | ").to_sym
  if csv_hash[key]
    csv_hash[key] << row
  else
    csv_hash[key] = [row]
  end
  #puts row #first row would be ["animal", "count", "price"] - etc.
end
puts "FINISHD"
CSV.open(destination_filename, "wb") do |csv|
  csv << ["Request URL", "Event count", "Events", "Request count"]
end

CSV.open(destination_filename, "a+") do |csv|
  csv_hash.each do |k,v|
    request_count = v.count{|request| request[5].blank? || request[5] == "CS1"}
    events = v.select{|request| request[5].present?}
    no_of_events = events.count
    events_string = events.map{|event| "#{event[5]} - #{event[6]}"}.join("\n")
    csv << [v[0][0], no_of_events, "\"#{events_string} \"", request_count]
  end
end
