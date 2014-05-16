require 'rubber/cloud/fog'

module Rubber
  module Cloud

    class Google < Fog

      def initialize(env, capistrano)
        compute_credentials = {
          :provider => 'Google',
          :google_project => env.cloud_providers.google.project_id,
          :google_client_email => env.cloud_providers.google.client_email,
          :google_key_location => env.cloud_providers.google.key_location
        }

        if env.cloud_providers && env.cloud_providers.aws
          storage_credentials = {
            :provider => 'Google',
            :google_storage_access_key_id     => env.cloud_providers.google.storage_access_key_id,
            :google_storage_secret_access_key => env.cloud_providers.google.storage_secret_access_key,
            :path_style => true
          }

          storage_credentials[:region] = env.cloud_providers.aws.region

          env['storage_credentials'] = storage_credentials
        end

        env['compute_credentials'] = compute_credentials
        super(env, capistrano)
      end

      def create_instance(instance_alias, image_name, image_type, security_groups, availability_zone, zone)
        begin
          # for example: 'us-central1-b'
          compute_provider.zones.get(zone)
        rescue
          raise "Invalid zone: #{zone}"
        end

        begin
          # for example: 'debian-7-wheezy-v20140415'
          compute_provider.images.get(image_name)
        rescue
          raise "Invalid image name: #{image_name}"
        end

        begin
          # for example: 'n1-standard-1'
          compute_provider.flavors.get(image_type)
        rescue
          raise "Invalid image type: #{image_type}"
        end

        response = compute_provider.servers.bootstrap(:name => "#{Rubber.env}-#{instance_alias}",
                                                    :source_image => image_name,
                                                    :machine_type => image_type,
                                                    :zone_name => zone,
                                                    :private_key_path => env.private_key_location,
                                                    :public_key_path => env.public_key_location)

        response.name
      end

      def describe_instances(instance_id=nil)
        instances = []
        opts = {}

        if instance_id
          response = [compute_provider.servers.get(instance_id)]
        else
          response = compute_provider.servers.all(opts)
        end

        response.each do |item|
          instance = {}
          instance[:id] = item.name
          instance[:state] = item.state
          instance[:type] = item.flavor_id
          instance[:external_ip] = item.public_ip_address
          instance[:internal_ip] = item.public_ip_address
          instance[:region_id] = item.region_id
          instance[:provider] = 'Google'
          instance[:platform] = Rubber::Platforms::LINUX
          instances << instance
        end

        return instances
      end

      def active_state
        'active'
      end
    end
  end
end
