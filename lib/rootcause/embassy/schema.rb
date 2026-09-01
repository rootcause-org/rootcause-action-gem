# frozen_string_literal: true

module RootCause
  module Embassy
    # Re-validates invocation params against the schema the invocation carries.
    # This is defense in depth: rootcause already validated at propose-time, but
    # the runner never trusts the wire. A violation is a hard refuse.
    #
    # Two schema shapes are accepted and normalized to one internal form, so the
    # gem is resilient to however the host serializes Appendix A's param schema:
    #
    #   map form (preferred):
    #     { "email" => { "type" => "string", "required" => true } }
    #
    #   JSON-Schema object form:
    #     { "type" => "object",
    #       "properties" => { "email" => { "type" => "string" } },
    #       "required"   => ["email"] }
    #
    # Supported types: string, integer, number, boolean, string[]. Unknown params
    # (present in the invocation but absent from the schema) are rejected.
    module Schema
      TYPES = %w[string integer number boolean string[]].freeze
      RESERVED_CONTEXT_PARAMS = %w[
        tenant_id tenant_slug tenant_scope_value
        principal_kind principal_external_id
      ].freeze

      module_function

      # Validate and return a frozen, symbol-keyed hash of coerced-but-not-mutated
      # values, ready to bind as data. Raises SchemaError on any violation.
      def validate!(params, schema)
        params ||= {}
        unless params.is_a?(Hash)
          raise SchemaError, "params must be an object"
        end

        specs = normalize(schema)
        params = stringify_keys(params)
        reserved = (params.keys + specs.keys).uniq.select { |name| reserved_context_param?(name) }
        unless reserved.empty?
          raise SchemaError, "trusted context is host-owned; reserved param(s): #{reserved.sort.join(", ")}"
        end

        unknown = params.keys - specs.keys
        unless unknown.empty?
          raise SchemaError, "unknown param(s): #{unknown.sort.join(", ")}"
        end

        out = {}
        specs.each do |name, spec|
          if params.key?(name)
            check_type!(name, params[name], spec.fetch(:type))
            out[name.to_sym] = deep_freeze(params[name])
          elsif spec[:required]
            raise SchemaError, "missing required param: #{name}"
          end
        end

        out.freeze
      end

      # @return [Hash{String=>{type:String, required:Boolean}}]
      def normalize(schema)
        raise SchemaError, "schema is missing" if schema.nil?
        raise SchemaError, "schema must be an object" unless schema.is_a?(Hash)

        schema = stringify_keys(schema)

        if schema["properties"].is_a?(Hash) || schema["type"] == "object"
          normalize_json_schema(schema)
        else
          normalize_map(schema)
        end
      end

      def normalize_json_schema(schema)
        props = stringify_keys(schema["properties"] || {})
        required = Array(schema["required"]).map(&:to_s)
        props.each_with_object({}) do |(name, spec), acc|
          spec = spec_hash!(name, spec)
          acc[name] = {type: type_of!(name, spec), required: required.include?(name)}
        end
      end

      def normalize_map(schema)
        schema.each_with_object({}) do |(name, spec), acc|
          spec = spec_hash!(name, spec)
          # required defaults to true in map form — param schemas are required
          # unless explicitly marked optional. Fail closed on absence.
          required = spec.key?("required") ? spec["required"] != false : true
          acc[name.to_s] = {type: type_of!(name, spec), required: required}
        end
      end

      # A spec must be an object carrying a `type`. A bare value (e.g. the
      # shorthand `{"email" => "string"}`) is a malformed schema — refuse it as a
      # SchemaError rather than letting a NoMethodError escape the pipeline.
      def spec_hash!(name, spec)
        raise SchemaError, "param #{name}: spec must be an object" unless spec.is_a?(Hash)

        stringify_keys(spec)
      end

      def type_of!(name, spec)
        type = spec["type"].to_s
        unless TYPES.include?(type)
          raise SchemaError, "param #{name}: unsupported type #{spec["type"].inspect}"
        end
        type
      end

      def check_type!(name, value, type)
        ok =
          case type
          when "string" then value.is_a?(String)
          when "integer" then value.is_a?(Integer) && !boolean?(value)
          when "number" then (value.is_a?(Integer) || value.is_a?(Float)) && !boolean?(value)
          when "boolean" then boolean?(value)
          when "string[]" then value.is_a?(Array) && value.all?(String)
          end

        unless ok
          raise SchemaError, "param #{name}: expected #{type}, got #{value.class}"
        end
      end

      def boolean?(value) = value == true || value == false

      def reserved_context_param?(name)
        normalized = name.downcase
        RESERVED_CONTEXT_PARAMS.include?(normalized) ||
          normalized.start_with?("rc_tenant_", "rc_principal_", "principal_claim_")
      end

      def stringify_keys(hash)
        hash.each_with_object({}) { |(k, v), acc| acc[k.to_s] = v }
      end

      # Freeze param values so an action cannot mutate the data it was handed and
      # leak state across runs. Strings/arrays are the only mutable shapes here.
      def deep_freeze(value)
        case value
        when Array then value.each { |e| deep_freeze(e) }.freeze
        else value.freeze
        end
      end
    end
  end
end
