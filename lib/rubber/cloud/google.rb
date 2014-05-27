require 'rubber/cloud/fog'

module Rubber
    module Cloud

        class Google < Fog

            def initialize(env, capistrano)
                @private_key_location ||= env.cloud_providers.google.private_key_location
                @public_key_location ||= env.cloud_providers.google.public_key_location

                compute_credentials = {
                    :provider => 'Google',
                    :google_project => env.cloud_providers.google.project_id,
                    :google_client_email => env.cloud_providers.google.client_email,
                    :google_key_location => env.cloud_providers.google.key_location
                }

                if env.cloud_providers && env.cloud_providers.google
                    storage_credentials = {
                        :provider => 'Google',
                        :google_storage_access_key_id => env.cloud_providers.google.storage_access_key_id,
                        :google_storage_secret_access_key => env.cloud_providers.google.storage_secret_access_key,
                        :path_style => true
                    }

                    storage_credentials[:region] = env.cloud_providers.google.region
                    env['storage_credentials'] = storage_credentials
                end

                env['compute_credentials'] = compute_credentials
                super(env, capistrano)
            end

            def before_create_instance(instance_alias, role_names)
                setup_network(instance_alias, role_names)
            end

            # def create_instance(instance_alias, ami, ami_type, security_groups, availability_zone, region, network)
            def create_instance(instance_alias, instance_roles, env)
                # rubber_cfg = Rubber::Configuration.get_configuration(Rubber.env)
                rubber_cfg = Rubber::Configuration.get_configuration(Rubber.env)
                # role_names = instance_roles.collect { |x| x.name }
                # env = rubber_cfg.environment.bind(role_names, instance_alias)

                cloud_env = env.cloud_providers[env.cloud_provider]
                image_id = cloud_env.image_id
                image_type = cloud_env.image_type
                availability_zone = cloud_env.availability_zone
                region = cloud_env.region
                network = (env.hosts[instance_alias] || env.hosts[Rubber.env]).network

                begin
                    # for example: 'us-central1-b'
                    compute_provider.zones.get(availability_zone)
                rescue
                    raise "Invalid zone: #{availability_zone}"
                end

                begin
                    # for example: 'debian-7-wheezy-v20140415'
                    compute_provider.images.get(image_id)
                rescue
                    raise "Invalid image name: #{image_id}"
                end

                begin
                    # for example: 'n1-standard-1'
                    compute_provider.flavors.get(image_type)
                rescue
                    raise "Invalid image type: #{image_type}"
                end

                begin
                    compute_provider.networks.get(network)
                rescue
                    raise "Invalid network: #{network}"
                end

                response = compute_provider.servers.create(:name => "#{Rubber.env}-#{instance_alias}",
                                                           :source_image => image_id,
                                                           :machine_type => image_type,
                                                           :zone_name => availability_zone,
                                                           :private_key_path => @private_key_location,
                                                           :public_key_path => @public_key_location,
                                                           :network => network)
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
                    instance[:internal_ip] = item.private_ip_address
                    instance[:region_id] = item.zone_name
                    instance[:provider] = 'Google'
                    instance[:platform] = Rubber::Platforms::LINUX
                    instances << instance
                end

                return instances
            end

            # https://developers.google.com/compute/docs/instances#checkmachinestatus
            def active_state
                'RUNNING'
            end

            def stopped_state
                'TERMINATED'
            end

            def setup_security_groups(host=nil, roles=[])
            end

            def setup_network(host=nil, roles=[])
                rubber_cfg = Rubber::Configuration.get_configuration(Rubber.env)
                scoped_env = rubber_cfg.environment.bind(roles, host)
                firewall_defns = scoped_env.firewalls.to_a
                route_defns = scoped_env.routes.to_a
                network_defns = scoped_env.networks.to_a
                # defns = firewall_defns.merge(route_defns).merge(network_defns)
                #
                # if scoped_env.auto_security_groups
                #     sghosts = (scoped_env.rubber_instances.collect { |ic| ic.name } + [host]).uniq.compact
                #     sgroles = (scoped_env.rubber_instances.all_roles + roles).uniq.compact
                #     defns = inject_auto_security_groups(defns, sghosts, sgroles)
                # end

                sync_networks(network_defns)
                sync_firewalls(firewall_defns)
                sync_routes(route_defns)
            end

            def sync_networks(networks)
                return unless networks

                networks = Rubber::Util::stringify(networks)
                # networks = isolate_groups(networks)
                network_names = networks.map { |n| n['name'] }

                cloud_networks = describe_networks()
                cloud_networks.each do |cloud_network|
                    network_name = cloud_network[:name]

                    # skip those groups that don't belong to this project/env
                    next if env.isolate_security_groups && network_name !~ /^#{isolate_prefix}/

                    if network_names.delete(network_name)
                        capistrano.logger.debug "Network already in cloud: #{network_name}"
                        networks.select { |a| a['name'] == network_name }

                        if network[:ipv4_range] == cloud_network[:ipv4_range]
                            capistrano.logger.debug "Network IPv4 range matches: #{network[:ipv4_range]}"
                        else
                            capistrano.logger.debug "Network IPv4 range DOES NOT match: #{network[:ipv4_range]}"
                            answer = Capistrano::CLI.ui.ask("Remove from and re-add to cloud? [y/N]: ")

                            if answer =~ /^y/
                                destroy_network(network_name)
                                create_network(network)
                            else
                                capistrano.logger.debug "Network *NOT* synced with local config: #{network_name}"
                            end
                        end
                    else
                        # delete network
                        answer = nil
                        msg = "Network '#{network_name}' exists in cloud but not locally"

                        if env.prompt_for_security_group_sync
                            answer = Capistrano::CLI.ui.ask("#{msg}, remove from cloud? [y/N]: ")
                        else
                            capistrano.logger.debug(msg)
                        end

                        destroy_network(network_name) if answer =~ /^y/
                    end
                end

                network_names.each do |network_name|
                    capistrano.logger.debug "Creating new network: #{network_name}"
                    network = networks.select { |a| a['name'] == network_name }
                    add_network_item(network[0]) if network.count > 0
                end
            end

            def sync_firewalls(networks)

            end

            def sync_routes(networks)

            end

            def add_network_item(rule_map)
                if rule_map['kind'] == "compute#firewall"
                    opts = {}
                    opts[:description] = rule_map['description'] if rule_map['description']
                    opts[:source_ranges] = rule_map['source_ranges'] if rule_map['source_ranges']
                    opts[:source_tags] = rule_map['source_tags'] if rule_map['source_tags']
                    opts[:target_tags] = rule_map['target_tags'] if rule_map['target_tags']

                    compute_provider.insert_firewall(rule_map['name'], rule_map['allowed'], rule_map['network'], opts)
                elsif rule_map['kind'] == "compute#route"
                    opts = {}
                    opts[:description] = rule_map['description'] if rule_map['description']
                    opts[:tags] = rule_map['tags'] if rule_map['tags']
                    opts[:nextHopInstance] = rule_map['nextHopInstance'] if rule_map['nextHopInstance']
                    opts[:nextHopGateway] = rule_map['nextHopGateway'] if rule_map['nextHopGateway']
                    opts[:nextHopIp] = rule_map['nextHopIp'] if rule_map['nextHopIp']
                    opts[:nextHopNetwork] = rule_map['nextHopNetwork'] if rule_map['nextHopNetwork']

                    compute_provider.insert_route(rule_map['name'], rule_map['network'], rule_map['destRange'], rule_map['priority'], opts)
                elsif rule_map['kind'] == "compute#network"
                    opts = {}
                    opts[:description] = rule_map['description'] if rule_map['description']
                    opts[:gatewayIPv4] = rule_map['gatewayIPv4'] if rule_map['gatewayIPv4']

                    compute_provider.insert_network(rule_map['name'], rule_map['IPv4Range'], opts)
                else
                    raise "unexpected network rule (#{rule_map['kind']}): #{rule_map}"
                end
            end

            def destroy_network(network_name)
                compute_provider.delete_network(network_name)
            end

            def describe_networks()
                networks = []
                cloud_networks = compute_provider.networks

                cloud_networks.each do |network|
                    cloud_network = {}
                    cloud_network[:kind] = network.kind
                    cloud_network[:id] = network.id
                    cloud_network[:name] = network.name
                    cloud_network[:ipv4_range] = network.ipv4_range
                    cloud_network[:description] = network.description if network.description
                    cloud_network[:gateway_ipv4] = network.gateway_ipv4 if network.gateway_ipv4
                    cloud_network[:self_link] = network.self_link if network.self_link

                    networks << cloud_network
                end

                networks
            end

            def describe_firewalls()
                firewalls = []
                cloud_firewalls = compute_provider.firewalls

                cloud_firewalls.each do |firewall|
                    cloud_firewall = {}
                    cloud_firewall[:kind] = firewall.kind
                    cloud_firewall[:id] = firewall.id
                    cloud_firewall[:name] = firewall.name
                    cloud_firewall[:description] = firewall.description if firewall.description
                    cloud_firewall[:network] = firewall.network
                    cloud_firewall[:self_link] = firewall.self_link
                    cloud_firewall[:sourceRanges] = firewall.source_ranges if firewall.source_ranges
                    cloud_firewall[:sourceTags] = firewall.source_tags if firewall.source_tags
                    cloud_firewall[:targetTags] = firewall.target_tags if firewall.target_tags

                    cloud_firewall.allowed.each do |protocol_port_pair|
                        cloud_firewall[:allowed] ||= []
                        rule = {}
                        rule[:IPProtocol] = protocol_port_pair.IPProtocol
                        rule[:ports] = protocol_port_pair.ports if protocol_port_pair.ports
                        cloud_firewall[:allowed] << rule
                    end if cloud_firewall.allowed

                    firewalls << cloud_firewall
                end

                firewalls
            end

            def describe_routes()
                routes = []
                cloud_routes = compute_provider.routes

                cloud_routes.each do |cloud_route|
                    cloud_route = {}
                    cloud_route[:kind] = route.kind
                    cloud_route[:id] = route.id
                    cloud_route[:name] = route.name
                    cloud_route[:description] = route.description
                    cloud_route[:network] = route.network
                    cloud_route[:dest_range] = route.dest_range
                    cloud_route[:priority] = route.priority
                    cloud_route[:self_link] = firewall.self_link
                    cloud_route[:next_hop_instance] = route.next_hop_instance if route.next_hop_instance
                    cloud_route[:next_hop_ip] = route.next_hop_ip if route.next_hop_ip
                    cloud_route[:next_hop_network] = route.next_hop_network if route.next_hop_network
                    cloud_route[:next_hop_gateway] = route.next_hop_gateway if route.next_hop_gateway
                    cloud_route[:tags] = route.tags if route.tags

                    cloud_route.warnings.each do |warning|
                        cloud_route[:warnings] ||= []
                        rule = {}

                        rule[:code] = warning.code
                        rule[:message] = warning.message

                        warning.data.each do |datum|
                            rule[:data] ||= []
                            datum_rule = {}

                            datum_rule[:key] = datum.key
                            datum_rule[:value] = datum.value

                            rule << datum_rule
                        end

                        cloud_route[:warnings] << rule
                    end if route.warnings

                    routes << cloud_route
                end

                routes
            end

            def create_volume(instance, volume_spec)
                volume = compute_provider.volumes.create(:size => volume_spec['size'], :availability_zone => volume_spec['zone'])
                volume.id
            end
        end
    end
end
