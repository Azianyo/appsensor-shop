require 'net/http'
require 'time'

module AppsensorAdditionalHelper

  def extract_nested_values_from_required_params(required_params, key)
    required_params.select{|param| param.is_a?(Hash) && param.keys[0] == key}[0].values[0]
  end

  def check_additional_params(params, required_params)
    params.all? do |k, v|
      if v.respond_to?(:keys)
        check_additional_params(v, extract_nested_values_from_required_params(required_params, k))
      else
        puts "Unrecognized parameter #{k}" unless required_params.include?(k)
        required_params.include?(k)
      end
    end
  end

  def params_too_long?(params)
    params.any? do |k,v|
      if v.respond_to?(:keys)
        params_too_long?(v)
      else
        v.length > 200
      end
    end
  end

  def params_contain_unexpected_chars?(params)
    params.any? do |k,v|
      next if k == "utf8"
      if v.respond_to?(:keys)
        params_contain_unexpected_chars?(v)
      else
        contains_unexpected_chars?(v)
      end
    end
  end

  def contains_unexpected_chars?(phrase)
    phrase.split('').map{ |c| c.unpack('C*') }.flatten.any?{ |v| v > 126 || v < 32 }
  end

  def headers_contain_line_break?
    request.headers.env.values.join.include?("\n")
  end

  def all_params?(parameters, required_params)
    required_params.all? do |name|
      if name.is_a?(Hash)
        unless parameters.key?(name.keys[0])
          puts "parameter missing #{name.keys[0]}"
          return false
        end
        all_params?(parameters[name.keys[0]], extract_nested_values_from_required_params(required_params, name.keys[0]))
      else
        puts "parameter missing #{name}" unless parameters.key?(name)
        parameters.key?(name)
      end
    end
  end

  def valid_encoding_in_params?(params)
    params.all? do |k,v|
      if v.respond_to?(:keys)
        valid_encoding_in_params?(v)
      else
        v.valid_encoding?
      end
    end
  end
end
