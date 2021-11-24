package hdinsight

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/hdinsight/mgmt/2018-06-01/hdinsight"
	"github.com/hashicorp/terraform-provider-azurerm/helpers/azure"
	"github.com/hashicorp/terraform-provider-azurerm/helpers/tf"
	"github.com/hashicorp/terraform-provider-azurerm/internal/clients"
	"github.com/hashicorp/terraform-provider-azurerm/internal/services/hdinsight/parse"
	"github.com/hashicorp/terraform-provider-azurerm/internal/tags"
	"github.com/hashicorp/terraform-provider-azurerm/internal/tf/pluginsdk"
	"github.com/hashicorp/terraform-provider-azurerm/internal/timeouts"
	"github.com/hashicorp/terraform-provider-azurerm/utils"
)

// NOTE: this isn't a recommended way of building resources in Terraform
// this pattern is used to work around a generic but pedantic API endpoint
var hdInsightHBaseClusterHeadNodeDefinition = HDInsightNodeDefinition{
	CanSpecifyInstanceCount:  false,
	MinInstanceCount:         2,
	MaxInstanceCount:         utils.Int(2),
	CanSpecifyDisks:          false,
	FixedTargetInstanceCount: utils.Int32(int32(2)),
}

var hdInsightHBaseClusterWorkerNodeDefinition = HDInsightNodeDefinition{
	CanSpecifyInstanceCount: true,
	MinInstanceCount:        1,
	CanSpecifyDisks:         false,
	CanAutoScaleOnSchedule:  true,
}

var hdInsightHBaseClusterWorkerNodeDefinitionWithAcceleratedWrites = HDInsightNodeDefinition{
	CanSpecifyInstanceCount: true,
	MinInstanceCount:        1,
	CanSpecifyDisks:         true,
	CanAutoScaleOnSchedule:  true,
	MaxNumberOfDisksPerNode: utils.Int(1),
}

var hdInsightHBaseClusterZookeeperNodeDefinition = HDInsightNodeDefinition{
	CanSpecifyInstanceCount:  false,
	MinInstanceCount:         3,
	MaxInstanceCount:         utils.Int(3),
	CanSpecifyDisks:          false,
	FixedTargetInstanceCount: utils.Int32(int32(3)),
}

func resourceHDInsightHBaseCluster() *pluginsdk.Resource {
	return &pluginsdk.Resource{
		Create: resourceHDInsightHBaseClusterCreate,
		Read:   resourceHDInsightHBaseClusterRead,
		Update: hdinsightClusterUpdate("HBase", resourceHDInsightHBaseClusterRead),
		Delete: hdinsightClusterDelete("HBase"),
		// TODO: replace this with an importer which validates the ID during import
		Importer: pluginsdk.DefaultImporter(),

		Timeouts: &pluginsdk.ResourceTimeout{
			Create: pluginsdk.DefaultTimeout(60 * time.Minute),
			Read:   pluginsdk.DefaultTimeout(5 * time.Minute),
			Update: pluginsdk.DefaultTimeout(60 * time.Minute),
			Delete: pluginsdk.DefaultTimeout(60 * time.Minute),
		},

		Schema: map[string]*pluginsdk.Schema{
			"name": SchemaHDInsightName(),

			"resource_group_name": azure.SchemaResourceGroupName(),

			"location": azure.SchemaLocation(),

			"cluster_version": SchemaHDInsightClusterVersion(),

			"tier": SchemaHDInsightTier(),

			"tls_min_version": SchemaHDInsightTls(),

			"enable_accelerated_writes": {
				Type:     pluginsdk.TypeBool,
				Optional: true,
				ForceNew: true,
				Default:  false,
			},

			"component_version": {
				Type:     pluginsdk.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &pluginsdk.Resource{
					Schema: map[string]*pluginsdk.Schema{
						"hbase": {
							Type:     pluginsdk.TypeString,
							Required: true,
							ForceNew: true,
						},
					},
				},
			},

			"gateway": SchemaHDInsightsGateway(),

			"metastores": SchemaHDInsightsExternalMetastores(),

			"security_profile": SchemaHDInsightsSecurityProfile(),

			"storage_account": SchemaHDInsightsStorageAccounts(),

			"storage_account_gen2": SchemaHDInsightsGen2StorageAccounts(),

			"roles": {
				Type:     pluginsdk.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &pluginsdk.Resource{
					Schema: map[string]*pluginsdk.Schema{
						"head_node": SchemaHDInsightNodeDefinition("roles.0.head_node", hdInsightHBaseClusterHeadNodeDefinition, true),

						"worker_node": SchemaHDInsightNodeDefinition("roles.0.worker_node", hdInsightHBaseClusterWorkerNodeDefinition, true),

						"zookeeper_node": SchemaHDInsightNodeDefinition("roles.0.zookeeper_node", hdInsightHBaseClusterZookeeperNodeDefinition, true),
					},
				},
			},

			"enable_disk_encryption": {
				Type:     schema.TypeList,
				Description: "Disk encryption using Customer Provided Keys or Platform Provided Keys",
				Optional: true,
				ForceNew: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"using_pmk": {
							Type:     schema.TypeBool,
							Description: "Disk encryption using Platform Provided Keys",
							Optional: true,
							ForceNew: true,
							ConflictsWith: []string{"enable_disk_encryption.0.using_cmk_key_url"},
							AtLeastOneOf: []string{"enable_disk_encryption.0.using_pmk", "enable_disk_encryption.0.using_cmk_key_url"},
						},
						"using_cmk_key_url": {
							Type:     schema.TypeString,
							Description: "Disk encryption using Customer Provided Keys",
							Optional: true,
							ConflictsWith: []string{"enable_disk_encryption.0.using_pmk"},
							RequiredWith: []string{"enable_disk_encryption.0.msi_resource_id"},
							AtLeastOneOf: []string{"enable_disk_encryption.0.using_pmk", "enable_disk_encryption.0.using_cmk_key_url"},
							ValidateFunc: func(i interface{}, k string) (warnings []string, errors []error) {
								value := i.(string)
								if value == "" {
									errors = append(errors, fmt.Errorf("`using_cmk_key_url` cannot be null or blank"))
								}
								return warnings, errors
							},
						},
						"msi_resource_id": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
							ConflictsWith: []string{"enable_disk_encryption.0.using_pmk"},
							ValidateFunc: func(i interface{}, k string) (warnings []string, errors []error) {
								value := i.(string)
								if value == "" {
									errors = append(errors, fmt.Errorf("`msi_resource_id` cannot be null or blank, when `using_cmk_key_url` is set"))
								}
								return warnings, errors
							},
						},
					},
				},
			},

			"tags": tags.Schema(),

			"https_endpoint": {
				Type:     pluginsdk.TypeString,
				Computed: true,
			},

			"ssh_endpoint": {
				Type:     pluginsdk.TypeString,
				Computed: true,
			},

			"monitor": SchemaHDInsightsMonitor(),
		},
	}
}

func resourceHDInsightHBaseClusterCreate(d *pluginsdk.ResourceData, meta interface{}) error {
	var encryptDataDisks *hdinsight.DiskEncryptionProperties
	var identity *hdinsight.ClusterIdentity
	var params hdinsight.ClusterCreateParametersExtended
	client := meta.(*clients.Client).HDInsight.ClustersClient
	subscriptionId := meta.(*clients.Client).Account.SubscriptionId
	extensionsClient := meta.(*clients.Client).HDInsight.ExtensionsClient
	ctx, cancel := timeouts.ForCreate(meta.(*clients.Client).StopContext, d)
	defer cancel()

	name := d.Get("name").(string)
	resourceGroup := d.Get("resource_group_name").(string)
	id := parse.NewClusterID(subscriptionId, resourceGroup, name)
	location := azure.NormalizeLocation(d.Get("location").(string))
	clusterVersion := d.Get("cluster_version").(string)
	t := d.Get("tags").(map[string]interface{})
	tier := hdinsight.Tier(d.Get("tier").(string))
	tls := d.Get("tls_min_version").(string)

	componentVersionsRaw := d.Get("component_version").([]interface{})
	componentVersions := expandHDInsightHBaseComponentVersion(componentVersionsRaw)

	gatewayRaw := d.Get("gateway").([]interface{})
	configurations := ExpandHDInsightsConfigurations(gatewayRaw)

	metastoresRaw := d.Get("metastores").([]interface{})
	metastores := expandHDInsightsMetastore(metastoresRaw)
	for k, v := range metastores {
		configurations[k] = v
	}

	storageAccountsRaw := d.Get("storage_account").([]interface{})
	storageAccountsGen2Raw := d.Get("storage_account_gen2").([]interface{})
	storageAccounts, identity, err := ExpandHDInsightsStorageAccounts(storageAccountsRaw, storageAccountsGen2Raw)
	if err != nil {
		return fmt.Errorf("failure expanding `storage_account`: %s", err)
	}
    enableAcceleratedWrites := d.Get("enable_accelerated_writes").(bool)
	hbaseRoles := decideHDInsightNodeDefinition(enableAcceleratedWrites)
	/*
	`enable_disk_encryption` block is optional, It supports both PMK and CMK
	 */
	enabledDiskEncryptionRaw := d.Get("enable_disk_encryption").([]interface{})
	if len(enabledDiskEncryptionRaw) > 0 {
		encryptDataDisks, err = hdInsightEncryptDataDiskProperties(enabledDiskEncryptionRaw)
		if err != nil {
			return fmt.Errorf("failure expanding `enable_disk_encryption`: %+v", err)
		}
		if encryptDataDisks.MsiResourceID != nil {
			identity = hdinsightUserDefinedClusterIdentity(*encryptDataDisks.MsiResourceID)
		}
	}
	rolesRaw := d.Get("roles").([]interface{})
	roles, err := expandHDInsightRoles(rolesRaw, hbaseRoles)
	if err != nil {
		return fmt.Errorf("failure expanding `roles`: %+v", err)
	}

	existing, err := client.Get(ctx, resourceGroup, name)
	if err != nil {
		if !utils.ResponseWasNotFound(existing.Response) {
			return fmt.Errorf("failure checking for presence of existing HDInsight HBase Cluster %q (Resource Group %q): %+v", name, resourceGroup, err)
		}
	}

	if existing.ID != nil && *existing.ID != "" {
		return tf.ImportAsExistsError("azurerm_hdinsight_hbase_cluster", *existing.ID)
	}

	if len(enabledDiskEncryptionRaw) > 0 {
		/*
		If `enable_disk_encryption` block is set then only add
		`DiskEncryptionProperties` to `params`
		 */
		params = hdinsight.ClusterCreateParametersExtended{
			Location: utils.String(location),
			Properties: &hdinsight.ClusterCreateProperties{
				Tier:                   tier,
				OsType:                 hdinsight.OSTypeLinux,
				ClusterVersion:         utils.String(clusterVersion),
				MinSupportedTLSVersion: utils.String(tls),
				ClusterDefinition: &hdinsight.ClusterDefinition{
					Kind:             utils.String("HBase"),
					ComponentVersion: componentVersions,
					Configurations:   configurations,
				},
				StorageProfile: &hdinsight.StorageProfile{
					Storageaccounts: storageAccounts,
				},
				ComputeProfile: &hdinsight.ComputeProfile{
					Roles: roles,
				},
				DiskEncryptionProperties: encryptDataDisks,
			},
			Tags:     tags.Expand(t),
			Identity: identity,
		}
	} else {
		params = hdinsight.ClusterCreateParametersExtended{
			Location: utils.String(location),
			Properties: &hdinsight.ClusterCreateProperties{
				Tier:                   tier,
				OsType:                 hdinsight.OSTypeLinux,
				ClusterVersion:         utils.String(clusterVersion),
				MinSupportedTLSVersion: utils.String(tls),
				ClusterDefinition: &hdinsight.ClusterDefinition{
					Kind:             utils.String("HBase"),
					ComponentVersion: componentVersions,
					Configurations:   configurations,
				},
				StorageProfile: &hdinsight.StorageProfile{
					Storageaccounts: storageAccounts,
				},
				ComputeProfile: &hdinsight.ComputeProfile{
					Roles: roles,
				},
			},
			Tags:     tags.Expand(t),
			Identity: identity,
		}
	}

	if v, ok := d.GetOk("security_profile"); ok {
		params.Properties.SecurityProfile = ExpandHDInsightSecurityProfile(v.([]interface{}))

		params.Identity = &hdinsight.ClusterIdentity{
			Type:                   hdinsight.ResourceIdentityTypeUserAssigned,
			UserAssignedIdentities: make(map[string]*hdinsight.ClusterIdentityUserAssignedIdentitiesValue),
		}

		if params.Properties.SecurityProfile != nil && params.Properties.SecurityProfile.MsiResourceID != nil {
			params.Identity.UserAssignedIdentities[*params.Properties.SecurityProfile.MsiResourceID] = &hdinsight.ClusterIdentityUserAssignedIdentitiesValue{}
		}
	}

	future, err := client.Create(ctx, resourceGroup, name, params)
	if err != nil {
		return fmt.Errorf("failure creating HDInsight HBase Cluster %q (Resource Group %q): %+v", name, resourceGroup, err)
	}

	if err := future.WaitForCompletionRef(ctx, client.Client); err != nil {
		return fmt.Errorf("failed waiting for creation of HDInsight HBase Cluster %q (Resource Group %q): %+v", name, resourceGroup, err)
	}

	read, err := client.Get(ctx, resourceGroup, name)
	if err != nil {
		return fmt.Errorf("failure retrieving HDInsight HBase Cluster %q (Resource Group %q): %+v", name, resourceGroup, err)
	}

	if read.ID == nil {
		return fmt.Errorf("failure reading ID for HDInsight HBase Cluster %q (Resource Group %q)", name, resourceGroup)
	}

	d.SetId(id.ID())

	// We can only enable monitoring after creation
	if v, ok := d.GetOk("monitor"); ok {
		monitorRaw := v.([]interface{})
		if err := enableHDInsightMonitoring(ctx, extensionsClient, resourceGroup, name, monitorRaw); err != nil {
			return err
		}
	}

	return resourceHDInsightHBaseClusterRead(d, meta)
}

func resourceHDInsightHBaseClusterRead(d *pluginsdk.ResourceData, meta interface{}) error {
	clustersClient := meta.(*clients.Client).HDInsight.ClustersClient
	configurationsClient := meta.(*clients.Client).HDInsight.ConfigurationsClient
	extensionsClient := meta.(*clients.Client).HDInsight.ExtensionsClient
	ctx, cancel := timeouts.ForRead(meta.(*clients.Client).StopContext, d)
	defer cancel()

	id, err := parse.ClusterID(d.Id())
	if err != nil {
		return err
	}

	resourceGroup := id.ResourceGroup
	name := id.Name

	resp, err := clustersClient.Get(ctx, resourceGroup, name)
	if err != nil {
		if utils.ResponseWasNotFound(resp.Response) {
			log.Printf("[DEBUG] HDInsight HBase Cluster %q was not found in Resource Group %q - removing from state!", name, resourceGroup)
			d.SetId("")
			return nil
		}

		return fmt.Errorf("failure retrieving HDInsight HBase Cluster %q (Resource Group %q): %+v", name, resourceGroup, err)
	}

	// Each call to configurationsClient methods is HTTP request. Getting all settings in one operation
	configurations, err := configurationsClient.List(ctx, resourceGroup, name)
	if err != nil {
		return fmt.Errorf("failure retrieving Configuration for HDInsight HBase Cluster %q (Resource Group %q): %+v", name, resourceGroup, err)
	}

	gateway, exists := configurations.Configurations["gateway"]
	if !exists {
		return fmt.Errorf("failure retrieving gateway for HDInsight HBase Cluster %q (Resource Group %q): %+v", name, resourceGroup, err)
	}

	d.Set("name", name)
	d.Set("resource_group_name", resourceGroup)
	if location := resp.Location; location != nil {
		d.Set("location", azure.NormalizeLocation(*location))
	}

	// storage_account isn't returned so I guess we just leave it ¯\_(ツ)_/¯
	if props := resp.Properties; props != nil {
		d.Set("cluster_version", props.ClusterVersion)
		d.Set("tier", string(props.Tier))
		d.Set("tls_min_version", props.MinSupportedTLSVersion)
		if props.DiskEncryptionProperties != nil {
			if err := d.Set("enable_disk_encryption", FlattenHDInsightsDiskEncryptionConfigurations(props.DiskEncryptionProperties)); err !=nil {
				return fmt.Errorf("failure flattening `enable_disk_encryption`: %+v", err)
			}
		}
		if def := props.ClusterDefinition; def != nil {
			if err := d.Set("component_version", flattenHDInsightHBaseComponentVersion(def.ComponentVersion)); err != nil {
				return fmt.Errorf("failure flattening `component_version`: %+v", err)
			}

			if err := d.Set("gateway", FlattenHDInsightsConfigurations(gateway, d)); err != nil {
				return fmt.Errorf("failure flattening `gateway`: %+v", err)
			}

			flattenHDInsightsMetastores(d, configurations.Configurations)
		}
		enableAcceleratedWrites := d.Get("enable_accelerated_writes").(bool)
		hbaseRoles := decideHDInsightNodeDefinition(enableAcceleratedWrites)
		flattenedRoles := flattenHDInsightRoles(d, props.ComputeProfile, hbaseRoles)
		if err := d.Set("roles", flattenedRoles); err != nil {
			return fmt.Errorf("failure flattening `roles`: %+v", err)
		}

		httpEndpoint := FindHDInsightConnectivityEndpoint("HTTPS", props.ConnectivityEndpoints)
		d.Set("https_endpoint", httpEndpoint)
		sshEndpoint := FindHDInsightConnectivityEndpoint("SSH", props.ConnectivityEndpoints)
		d.Set("ssh_endpoint", sshEndpoint)

		monitor, err := extensionsClient.GetMonitoringStatus(ctx, resourceGroup, name)
		if err != nil {
			return fmt.Errorf("failed reading monitor configuration for HDInsight Hadoop Cluster %q (Resource Group %q): %+v", name, resourceGroup, err)
		}

		d.Set("monitor", flattenHDInsightMonitoring(monitor))

		if err := d.Set("security_profile", flattenHDInsightSecurityProfile(props.SecurityProfile, d)); err != nil {
			return fmt.Errorf("setting `security_profile`: %+v", err)
		}
	}

	return tags.FlattenAndSet(d, resp.Tags)
}

func expandHDInsightHBaseComponentVersion(input []interface{}) map[string]*string {
	vs := input[0].(map[string]interface{})
	return map[string]*string{
		"hbase": utils.String(vs["hbase"].(string)),
	}
}

func flattenHDInsightHBaseComponentVersion(input map[string]*string) []interface{} {
	hbaseVersion := ""
	if v, ok := input["hbase"]; ok {
		if v != nil {
			hbaseVersion = *v
		}
	}
	return []interface{}{
		map[string]interface{}{
			"hbase": hbaseVersion,
		},
	}
}

func decideHDInsightNodeDefinition(enableWrites bool) hdInsightRoleDefinition {
	var hbaseRoles hdInsightRoleDefinition
	if enableWrites {
		hbaseRoles = hdInsightRoleDefinition{
			HeadNodeDef:      hdInsightHBaseClusterHeadNodeDefinition,
			WorkerNodeDef:    hdInsightHBaseClusterWorkerNodeDefinitionWithAcceleratedWrites,
			ZookeeperNodeDef: hdInsightHBaseClusterZookeeperNodeDefinition,
		}
	} else {
		hbaseRoles = hdInsightRoleDefinition{
			HeadNodeDef:      hdInsightHBaseClusterHeadNodeDefinition,
			WorkerNodeDef:    hdInsightHBaseClusterWorkerNodeDefinition,
			ZookeeperNodeDef: hdInsightHBaseClusterZookeeperNodeDefinition,
		}
	}
	return hbaseRoles
}