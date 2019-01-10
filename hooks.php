<?php
function hook_pricesautocalc_run($vars) {
	global $smarty;
	if (!file_exists(dirname(__FILE__).DIRECTORY_SEPARATOR."pricesautocalc.php")) {
		$smarty->_tpl_vars['PAUTOC']['enabled'] = false;
	} else {
		$smarty->_tpl_vars['PAUTOC']['enabled'] = true;
		require_once(realpath(dirname(__FILE__).DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."configuration.php"));
		$conn = mysql_connect($db_host, $db_username, $db_password);
		mysql_select_db($db_name, $conn);
		if (file_exists(dirname(__FILE__).DIRECTORY_SEPARATOR."lang".DIRECTORY_SEPARATOR.strtolower($smarty->_tpl_vars['language']).".php")) {
			require_once(dirname(__FILE__).DIRECTORY_SEPARATOR."lang".DIRECTORY_SEPARATOR.strtolower($smarty->_tpl_vars['language']).".php");
		} /*else {
			require_once(dirname(__FILE__).DIRECTORY_SEPARATOR."lang".DIRECTORY_SEPARATOR."english.php");
		}*/
		if ($_SERVER['HTTPS'] == "on" || $_SERVER['SERVER_PORT'] == 443) {
			$whmcsurl = $smarty->_tpl_vars['systemsslurl'];
		} else {
			$whmcsurl = $smarty->_tpl_vars['systemurl'];
		}
		# Get API User
		$resultAPI = mysql_query("SELECT `value` FROM `tbladdonmodules` WHERE `module`='pricesautocalc' AND `setting`='adminuser'");
		$dataAPI = mysql_fetch_array($resultAPI);
		$apiadminuser = $dataAPI['value'];
		# End
		# Get Current Module Configuration
		$result = mysql_query("SELECT * FROM `mod_pricesautocalc`");
		while ($data = mysql_fetch_array($result)) {
			if ($data['activated'] == 1) {
				switch ($data['action']) {
					case "domains":
						$command = "updateclientdomain";
						$adminuser = $apiadminuser;
						$valuesdomains = array();
						$values["autorecalc"] = true;
						# Create SQL Query for Domains
						$table = "tbldomains";
						$fields = "id, domain, userid, promoid";
						$where = array();
						if ($data['includenotactive'] <> 1) {
							$where["status"] = "Active";
						}
						# End
						# Get List of Domains
						$resultDomains = select_query($table,$fields,$where);
						# End
						# Iterate Domains and Autorecalc
						global $currency;
						while ($dataDomains = mysql_fetch_array($resultDomains)) {
							$values["domainid"] = $dataDomains['id'];
							//$values["domain"] = $dataDomains['domain'];
							$values["promoid"] = $dataDomains['promoid'];
							$userid = $dataDomains['userid'];
							$domainparts = explode(".", $dataDomains['domain'], 2);
							$currency = getCurrency($userid);
							$results = localAPI($command,$values,$adminuser);
							$valuesdomains[$dataDomains['domain']] = $results;
						}
						# End
						logModuleCall("pricesautocalc","cron_update",$command,$valuesdomains);
						echo "Prices Autocalc Addon: Domain Prices Update OK\n";
						break;
					case "products":
						$command = "updateclientproduct";
						$adminuser = $apiadminuser;
						$valuesproducts = array();
						$values["autorecalc"] = "1";
						# Create SQL Query
						$table = "tblhosting";
						$fields = "id, domain";
						$where = array();
						if ($data['includefree'] <> 1) {
							$where["billingcycle"] = array("sqltype"=>"NEQ","value"=>"Free Account");
							}
						if ($data['includenotactive'] <> 1) {
							$where["domainstatus"] = "Active";
							}
						# End
						# Get List of Products
						$resultProducts = select_query($table,$fields,$where);
						# End
						# Iterate Products and Autorecalc
						while ($dataProducts = mysql_fetch_array($resultProducts)) {
							$values["serviceid"] = $dataProducts['id'];
							$values["domain"] = $dataProducts['domain'];
							$results = localAPI($command,$values,$adminuser);
							$valuesproducts[$values["domain"]] = $results;
						}
						# End
						logModuleCall("pricesautocalc","cron_update",$command,$valuesproducts);
						echo "Prices Autocalc Addon: Product Prices Update OK\n";
						break;
				}
			}
		}
		# End
	}
}

# Get ManualCron Config
$table = "tbladdonmodules";
$fields = "value";
$where = array("module"=>"pricesautocalc","setting"=>"manualcron");
$result = select_query($table,$fields,$where);
$data = mysql_fetch_array($result);
# End Get ManualCron
if (empty($data['value'])) {add_hook("DailyCronJobPreEmail", 999, "hook_pricesautocalc_run");}
?>