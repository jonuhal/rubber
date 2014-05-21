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
                        :google_storage_access_key_id => env.cloud_providers.google.storage_access_key_id,
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
                rubber_cfg = Rubber::Configuration.get_configuration(Rubber.env)
                scoped_env = rubber_cfg.environment.bind(roles, host)
                firewall_defns = Hash[scoped_env.firewalls.to_a]
                route_defns = Hash[scoped_env.routes.to_a]
                defns = firewall_defns.merge(route_defns)

                if scoped_env.auto_security_groups
                    sghosts = (scoped_env.rubber_instances.collect { |ic| ic.name } + [host]).uniq.compact
                    sgroles = (scoped_env.rubber_instances.all_roles + roles).uniq.compact
                    defns = inject_auto_security_groups(defns, sghosts, sgroles)
                end

                sync_security_groups(defns)
            end

            def sync_security_groups(groups)
                return unless groups

                groups = Rubber::Util::stringify(groups)
                groups = isolate_groups(groups)
                group_keys = groups.keys.clone()

                # For each group that does already exist in cloud
                cloud_groups = describe_network_rules()
                cloud_groups.each do |cloud_group|
                    group_name = cloud_group[:name]

                    # skip those groups that don't belong to this project/env
                    next if env.isolate_security_groups && group_name !~ /^#{isolate_prefix}/

                    if group_keys.delete(group_name)
                        # sync rules
                        capistrano.logger.debug "Security Group already in cloud, syncing rules: #{group_name}"
                        group = groups[group_name]

                        # convert the special case default rule into what it actually looks like when
                        # we query ec2 so that we can match things up when syncing
                        rules = group['rules'].clone
                        group['rules'].each do |rule|
                            if [2, 3].include?(rule.size) && rule['source_group_name'] && rule['source_group_account']
                                rules << rule.merge({'protocol' => 'tcp', 'from_port' => '1', 'to_port' => '65535'})
                                rules << rule.merge({'protocol' => 'udp', 'from_port' => '1', 'to_port' => '65535'})
                                rules << rule.merge({'protocol' => 'icmp', 'from_port' => '-1', 'to_port' => '-1'})
                                rules.delete(rule)
                            end
                        end

                        rule_maps = []

                        # first collect the rule maps from the request (group/user pairs are duplicated for tcp/udp/icmp,
                        # so we need to do this up frnot and remove duplicates before checking against the local rubber rules)
                        cloud_group[:allowed].each do |rule|
                            source_groups = rule.delete(:source_groups)
                            if source_groups
                                source_groups.each do |source_group|
                                    rule_map = rule.clone
                                    rule_map.delete(:source_ips)
                                    rule_map[:source_group_name] = source_group[:name]
                                    rule_map[:source_group_account] = source_group[:account]
                                    rule_map = Rubber::Util::stringify(rule_map)
                                    rule_maps << rule_map unless rule_maps.include?(rule_map)
                                end
                            else
                                rule_map = Rubber::Util::stringify(rule)
                                rule_maps << rule_map unless rule_maps.include?(rule_map)
                            end
                        end if cloud_group[:allowed]
                        # For each rule, if it exists, do nothing, otherwise remove it as its no longer defined locally
                        rule_maps.each do |rule_map|
                            if rules.delete(rule_map)
                                # rules match, don't need to do anything
                                # logger.debug "Rule in sync: #{rule_map.inspect}"
                            else
                                # rules don't match, remove them from cloud and re-add below
                                answer = nil
                                msg = "Rule '#{rule_map.inspect}' exists in cloud, but not locally"
                                if env.prompt_for_security_group_sync
                                    answer = Capistrano::CLI.ui.ask("#{msg}, remove from cloud? [y/N]: ")
                                else
                                    capistrano.logger.info(msg)
                                end

                                if answer =~ /^y/
                                    rule_map = Rubber::Util::symbolize_keys(rule_map)
                                    if rule_map[:source_group_name]
                                        remove_network_rule(group_name, rule_map[:protocol], rule_map[:from_port], rule_map[:to_port], {:name => rule_map[:source_group_name], :account => rule_map[:source_group_account]})
                                    else
                                        rule_map[:source_ips].each do |source_ip|
                                            remove_network_rule(group_name, rule_map[:protocol], rule_map[:from_port], rule_map[:to_port], source_ip)
                                        end if rule_map[:source_ips]
                                    end
                                end
                            end
                        end

                        rules.each do |rule_map|
                            # create non-existing rules
                            capistrano.logger.debug "Missing rule, creating: #{rule_map.inspect}"
                            rule_map = Rubber::Util::symbolize_keys(rule_map)
                            if rule_map[:source_group_name]
                                add_security_group_rule(group_name, rule_map[:protocol], rule_map[:from_port], rule_map[:to_port], {:name => rule_map[:source_group_name], :account => rule_map[:source_group_account]})
                            else
                                rule_map[:source_ips].each do |source_ip|
                                    add_security_group_rule(group_name, rule_map[:protocol], rule_map[:from_port], rule_map[:to_port], source_ip)
                                end if rule_map[:source_ips]
                            end
                        end
                    else
                        # delete group
                        answer = nil
                        msg = "Security group '#{group_name}' exists in cloud but not locally"
                        if env.prompt_for_security_group_sync
                            answer = Capistrano::CLI.ui.ask("#{msg}, remove from cloud? [y/N]: ")
                        else
                            capistrano.logger.debug(msg)
                        end
                        # destroy_security_group(group_name) if answer =~ /^y/
                    end
                end

                # For each group that didnt already exist in cloud
                group_keys.each do |group_name|
                    group = groups[group_name]
                    # capistrano.logger.debug "Creating new security group: #{group_name}"
                    # create each group
                    # create_security_group(group_name, group['description'])
                    # create rules for group
                    group['rules'].each do |rule_map|
                        capistrano.logger.debug "Creating new rule: #{rule_map.inspect}"
                        rule_map = Rubber::Util::symbolize_keys(rule_map)
                        add_network_rule(rule_map)
                    end
                end
            end

            def add_network_rule(rule_map)
                if rule_map[:kind] == "compute#firewall"
                    opts = {}
                    opts[:description] = rule_map[:description] if rule_map[:description]
                    opts[:source_ranges] = rule_map[:source_ranges] if rule_map[:source_ranges]
                    opts[:source_tags] = rule_map[:source_tags] if rule_map[:source_tags]
                    opts[:target_tags] = rule_map[:target_tags] if rule_map[:target_tags]

                    compute_provider.insert_firewall(rule_map[:name], rule_map[:allowed], rule_map[:network], opts)
                elsif rule_map[:kind] == "compute#route"
                    opts = {}
                    opts[:description] = rule_map[:description] if rule_map[:description]
                    opts[:tags] = rule[:tags] if rule_map[:tags]
                    opts[:nextHopInstance] = rule_map[:nextHopInstance] if rule_map[:nextHopInstance]
                    opts[:nextHopGateway] = rule_map[:nextHopGateway] if rule_map[:nextHopGateway]
                    opts[:nextHopIp] = rule_map [:nextHopIp] if rule_map[:nextHopIp]
                    opts[:nextHopNetwork] = rule_map[:nextHopNetwork] if rule_map[:nextHopNetwork]

                    compute_provider.insert_route(rule_map[:name], rule_map[:network], rule_map[:destRange], rule_map[:priority], opts)
                else
                    raise "unexpected network rule (#{rule_map[:kind]}): #{rule_map}"
                end
            end

            def describe_network_rules(identity=nil)
                groups = []

                opts = {}
                opts["identity"] = identity if identity
                firewalls = compute_provider.firewalls(opts)
                routes = compute_provider.routes(opts)

                firewalls.each do |firewall|
                    group = {}
                    group[:kind] = firewall.kind
                    group[:id] = firewall.id
                    group[:name] = firewall.name
                    group[:description] = firewall.description
                    group[:network] = firewall.network
                    group[:sourceRanges] = firewall.source_ranges
                    group[:sourceTags] = firewall.source_tags if firewall.source_tags
                    group[:targetTags] = firewall.target_tags if firewall.target_tags

                    firewall.allowed.each do |ip_item|
                        group[:allowed] ||= []
                        rule = {}

                        rule[:protocol] = ip_item["IPProtocol"]
                        rule[:ports] = ip_item["ports"] if ip_item["ports"]

                        group[:allowed] << rule
                    end

                    groups << group
                end

                routes.each do |route|
                    group = {}
                    group[:kind] = route.kind
                    group[:id] = route.id
                    group[:name] = route.name
                    group[:description] = route.description
                    group[:network] = route.network
                    group[:destRange] = route.dest_range
                    group[:priority] = route.priority
                    group[:nextHopInstance] = route.next_hop_instance if route.next_hop_instance
                    group[:nextHopIp] = route.next_hop_ip if route.next_hop_ip
                    group[:nextHopNetwork] = route.next_hop_network if route.next_hop_network
                    group[:nextHopGateway] = route.next_hop_gateway if route.next_hop_gateway
                    group[:tags] = route.tags if route.tags

                    route.warnings.each do |warning|
                        group[:warnings] ||= []
                        rule = {}

                        rule[:code] = warning["code"]
                        rule[:message] = warning["message"]

                        warning.data.each do |datum|
                            rule[:data] ||= []
                            datum_rule = {}

                            datum_rule[:key] = datum[:key]
                            datum_rule[:value] = datum[:value]

                            rule << datum_rule
                        end

                        group[:warnings] << rule
                    end if route.warnings

                    groups << group
                end

                groups
            end

            # def destroy_security_group(group_name)
            # end
        end
    end
end
