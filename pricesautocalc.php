<?php
# This prevents any direct access
if (!defined("WHMCS")) {
	exit("This file cannot be accessed directly");
}

# Replace "yourprefix" with your own unique prefix to avoid conflicts with
# other instances of the licensing addon included within the same scope
function pricesautocalc_check_license($licensekey, $localkey='') {

    # -----------------------------------
    #  -- Configuration Values --
    # -----------------------------------

    # Enter the url to your WHMCS installation here
    $whmcsurl = 'HTTPS://WWW.YOURDOMAIN.COM/';
    # Must match what is specified in the MD5 Hash Verification field
    # of the licensing product that will be used with this check.
    $licensing_secret_key = 'XXXXXXXXXXXXXXXXXXX';
    # The number of days to wait between performing remote license checks
    $localkeydays = 15;
    # The number of days to allow failover for after local key expiry
    $allowcheckfaildays = 5;

    # -----------------------------------
    #  -- Do not edit below this line --
    # -----------------------------------

    $check_token = time() . md5(mt_rand(1000000000, 9999999999) . $licensekey);
    $checkdate = date("Ymd");
    $domain = $_SERVER['SERVER_NAME'];
    $usersip = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : $_SERVER['LOCAL_ADDR'];
    $dirpath = dirname(__FILE__);
    $verifyfilepath = 'modules/servers/licensing/verify.php';
    $localkeyvalid = false;
    if ($localkey) {
        $localkey = str_replace("\n", '', $localkey); # Remove the line breaks
        $localdata = substr($localkey, 0, strlen($localkey) - 32); # Extract License Data
        $md5hash = substr($localkey, strlen($localkey) - 32); # Extract MD5 Hash
        if ($md5hash == md5($localdata . $licensing_secret_key)) {
            $localdata = strrev($localdata); # Reverse the string
            $md5hash = substr($localdata, 0, 32); # Extract MD5 Hash
            $localdata = substr($localdata, 32); # Extract License Data
            $localdata = base64_decode($localdata);
            $localkeyresults = unserialize($localdata);
            $originalcheckdate = $localkeyresults['checkdate'];
            if ($md5hash == md5($originalcheckdate . $licensing_secret_key)) {
                $localexpiry = date("Ymd", mktime(0, 0, 0, date("m"), date("d") - $localkeydays, date("Y")));
                if ($originalcheckdate > $localexpiry) {
                    $localkeyvalid = true;
                    $results = $localkeyresults;
                    $validdomains = explode(',', $results['validdomain']);
                    if (!in_array($_SERVER['SERVER_NAME'], $validdomains)) {
                        $localkeyvalid = false;
                        $localkeyresults['status'] = "Invalid";
                        $results = array();
                    }
                    $validips = explode(',', $results['validip']);
                    if (!in_array($usersip, $validips)) {
                        $localkeyvalid = false;
                        $localkeyresults['status'] = "Invalid";
                        $results = array();
                    }
                    $validdirs = explode(',', $results['validdirectory']);
                    if (!in_array($dirpath, $validdirs)) {
                        $localkeyvalid = false;
                        $localkeyresults['status'] = "Invalid";
                        $results = array();
                    }
					echo $query_string;
                }
            }
        }
    }
    if (!$localkeyvalid) {
        $postfields = array(
            'licensekey' => $licensekey,
            'domain' => $domain,
            'ip' => $usersip,
            'dir' => $dirpath,
        );
        if ($check_token) $postfields['check_token'] = $check_token;
        $query_string = '';
        foreach ($postfields AS $k=>$v) {
            $query_string .= $k.'='.urlencode($v).'&';
        }
        if (function_exists('curl_exec')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $whmcsurl . $verifyfilepath);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $query_string);
            curl_setopt($ch, CURLOPT_TIMEOUT, 30);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            $data = curl_exec($ch);
            curl_close($ch);
        } else {
            $fp = fsockopen($whmcsurl, 80, $errno, $errstr, 5);
            if ($fp) {
                $newlinefeed = "\r\n";
                $header = "POST ".$whmcsurl . $verifyfilepath . " HTTP/1.0" . $newlinefeed;
                $header .= "Host: ".$whmcsurl . $newlinefeed;
                $header .= "Content-type: application/x-www-form-urlencoded" . $newlinefeed;
                $header .= "Content-length: ".@strlen($query_string) . $newlinefeed;
                $header .= "Connection: close" . $newlinefeed . $newlinefeed;
                $header .= $query_string;
                $data = '';
                @stream_set_timeout($fp, 20);
                @fputs($fp, $header);
                $status = @socket_get_status($fp);
                while (!@feof($fp)&&$status) {
                    $data .= @fgets($fp, 1024);
                    $status = @socket_get_status($fp);
                }
                @fclose ($fp);
            }
        }
        if (!$data) {
            $localexpiry = date("Ymd", mktime(0, 0, 0, date("m"), date("d") - ($localkeydays + $allowcheckfaildays), date("Y")));
            if ($originalcheckdate > $localexpiry) {
                $results = $localkeyresults;
            } else {
                $results = array();
                $results['status'] = "Invalid";
                $results['description'] = "Remote Check Failed";
                return $results;
            }
        } else {
            preg_match_all('/<(.*?)>([^<]+)<\/\\1>/i', $data, $matches);
            $results = array();
            foreach ($matches[1] AS $k=>$v) {
                $results[$v] = $matches[2][$k];
            }
        }
        if (!is_array($results)) {
            die("Invalid License Server Response");
        }
        if ($results['md5hash']) {
            if ($results['md5hash'] != md5($licensing_secret_key . $check_token)) {
                $results['status'] = "Invalid";
                $results['description'] = "MD5 Checksum Verification Failed";
                return $results;
            }
        }
        if ($results['status'] == "Active") {
            $results['checkdate'] = $checkdate;
            $data_encoded = serialize($results);
            $data_encoded = base64_encode($data_encoded);
            $data_encoded = md5($checkdate . $licensing_secret_key) . $data_encoded;
            $data_encoded = strrev($data_encoded);
            $data_encoded = $data_encoded . md5($data_encoded . $licensing_secret_key);
            $data_encoded = wordwrap($data_encoded, 80, "\n", true);
            $results['localkey'] = $data_encoded;
        }
        $results['remotecheck'] = true;
    }
    unset($postfields,$data,$matches,$whmcsurl,$licensing_secret_key,$checkdate,$usersip,$localkeydays,$allowcheckfaildays,$md5hash);
    return $results;
}

function pricesautocalc_config() {
	$configarray = array(
		"name" => "Prices AutoCalc",
		"description" => "This is an addon module that will update selling prices on existing domains and products for your customers.",
		"version" => "1.2.3",
		"nextduedate" => "",
		"author" => "<a href='HTTPS://WWW.YOURDOMAIN.COM/'><img src='HTTPS://WWW.YOURDOMAIN.COM/YOURIMAGE.png' alt='YOUR COMPANY NAME'></a>",
		"language" => "english",
		"fields" => array(
			"licensekey" => array(
				"FriendlyName" => "License Key",
				"Type" => "text",
				"Size" => "30",
				"Description" => "",
				"Default" => "PAUTOC-"
				),
			"timeout" => array(
				"FriendlyName" => "Time Out",
				"Type" => "text",
				"Size" => "30",
				"Description" =>
				"The amount of time the script will try to contact the Server before giving up",
				"Default" => "30"
				),
			"adminuser" => array(
				"FriendlyName" => "API User",
				"Type" => "text",
				"Size" => "15",
				"Description" => "WHMCS User who will run queries",
				"Default" => "admin"
				)
			)
		);
	return $configarray;
}

function pricesautocalc_activate() {
    # Create Custom DB Table
	$query = "CREATE TABLE `mod_pricesautocalc` (`id` int(1) NOT NULL AUTO_INCREMENT PRIMARY KEY,`action` text NOT NULL,`activated` tinyint(1) DEFAULT NULL, `includefree` BOOLEAN NOT NULL , `includenotactive` BOOLEAN NOT NULL)";
    $result = full_query($query);
	$query = "INSERT INTO `mod_pricesautocalc` (`id`, `action`, `activated`, `includefree`, `includenotactive`) VALUES (NULL, 'domains', NULL, 0, 0), (NULL, 'products', NULL, 0, 0)";
    $result = full_query($query);
	$table = "tbladdonmodules";
	$values = array("module"=>"pricesautocalc","setting"=>"localkey","value"=>"");
	$newid = insert_query($table,$values);
	$table = "tbladdonmodules";
	$values = array("module"=>"pricesautocalc","setting"=>"manualcron","value"=>FALSE);
	$newid = insert_query($table,$values);
   # Return Result
    return array('status'=>'success','description'=>'Module succesfully activated');
    return array('status'=>'error','description'=>'There was an error while activating module. Please contact Support.');
    return array('status'=>'info','description'=>'');
}

function pricesautocalc_deactivate() {
    # Remove Custom DB Table
    $query = "DROP TABLE `mod_pricesautocalc`";
    $result = full_query($query);
	# Remove Localkey Information
    $query = "DELETE FROM `tbladdonmodules` WHERE `module`='pricesautocalc' AND `setting` = 'localkey'";
    $result = full_query($query);
	# Remove Manual Cron Information
    $query = "DELETE FROM `tbladdonmodules` WHERE `module`='pricesautocalc' AND `setting` = 'manualcron'";
    $result = full_query($query);
    # Return Result
    return array('status'=>'success','description'=>'Module succesfully deactivated');
    return array('status'=>'error','description'=>'There was an error while deactivating module. Please contact Support.');
    return array('status'=>'info','description'=>'');
}

function pricesautocalc_upgrade($vars) {
    $version = $vars['version'];
    # Run SQL Updates for V1.0 to V1.1
    if ($version < 1.1) {
		# Modify SQL
        $query = "ALTER TABLE `mod_pricesautocalc` ADD `includefree` BOOLEAN NOT NULL , ADD `includenotactive` BOOLEAN NOT NULL ;";
        $result = full_query($query);

		$table = "tbladdonmodules";
		$values = array("module"=>"pricesautocalc","setting"=>"localkey","value"=>"");
		$newid = insert_query($table,$values);
		$table = "tbladdonmodules";
		$values = array("module"=>"pricesautocalc","setting"=>"manualcron","value"=>FALSE);
		$newid = insert_query($table,$values);
    }
}

function pricesautocalc_output($vars) {
	$modulelink = $vars['modulelink'];
	$version = $vars['version'];
	$timeout = $vars['timeout'];
	$LANG = $vars['_lang'];
	# Validate License
	$licensekey = $vars['licensekey'];
	# Get Localkey
	$table = "tbladdonmodules";
	$fields = "value";
	$where = array("module"=>"pricesautocalc","setting"=>"localkey");
	$result = select_query($table,$fields,$where);
	$data = mysql_fetch_array($result);
	$localkey = $data['value'];
	# Validate License Key
	$results = pricesautocalc_check_license($licensekey, $localkey);
	# Raw output of results for debugging purpose
	# echo $localkey.'<br/>';
	# echo '<textarea cols="100" rows="20">' . print_r($results, true) . '</textarea><br/>';
	# Interpret response
	switch ($results['status']) {
		case "Active":
			# get new local key and save it somewhere
			if (isset($results['localkey'])) {
				$localkeydata = $results['localkey'];
				$table = "tbladdonmodules";
				$update = array('value'=>$localkeydata);
				$where = array('module'=>'pricesautocalc','setting'=>'localkey');
				update_query($table,$update,$where);
			}
			$vars['nextduedate'] = $results['nextduedate'];
			echo($LANG['pricesautocalc_output_license_exp'].$results['nextduedate']."<br>");
			pricesautocalc_showform($vars);
			break;
		case "Invalid":
			echo("<div class='infobox'>".$LANG['pricesautocalc_output_lic_nook']."</div>");
			break;
		case "Expired":
			echo("<div class='errorbox'>".$LANG['pricesautocalc_output_lic_exp']."</div>");
			break;
		case "Suspended":
			echo("<div class='infobox'>".$LANG['pricesautocalc_output_lic_susp']."</div>");
			break;
		default:
			echo($LANG['pricesautocalc_output_lic_inv']);
			break;
	}
	# End Validate License Key
}

function pricesautocalc_showform($vars) {
	$LANG = $vars['_lang'];
	$whmcspath = substr(getcwd(),0,strrpos(getcwd(),'/'));
	$addonpath = $whmcspath."/modules/addons/pricesautocalc";
	$locallicensekey = $addonpath."/PAUTOC.key";
	if (file_exists($locallicensekey)) {
		echo("<div class='errorbox'>".str_replace('%FILE%',$locallicensekey,$LANG['pricesautocalc_showform_err_pautockey'])."</div>");
		echo "<button class='btn btn-success' onclick='location.reload(true);'>".$LANG['pricesautocalc_showform_err_refresh']."</button>";
	} else {
		# Get API user
		$table = "tbladdonmodules";
		$fields = "value";
		$where = array("module"=>"pricesautocalc","setting"=>"adminuser");
		$result = select_query($table,$fields,$where);
		$data = mysql_fetch_array($result);
		$apiadminuser = $data['value'];
		# End

		# If ENABLE/DISABLE button was pressed, call to action
		if (isset($_POST['enableaction'])) {
			switch ($_POST['enableaction']) {
				case "Enable Domains" :
				case "Activar Dominios" :
					$queryupdate = "UPDATE `mod_pricesautocalc` SET `activated`=1 WHERE `action`='domains' ";
					break;
				case "Disable Domains" :
				case "Desactivar Dominios" :
					$queryupdate = "UPDATE `mod_pricesautocalc` SET `activated`=0 WHERE `action`='domains' ";
					break;
				case "Enable Products" :
				case "Activar Productos" :
					$queryupdate = "UPDATE `mod_pricesautocalc` SET `activated`=1 WHERE `action`='products' ";
					break;
				case "Disable Products" :
				case "Desactivar Productos" :
					$queryupdate = "UPDATE `mod_pricesautocalc` SET `activated`=0 WHERE `action`='products' ";
					break;
			}
			$resultupdate = full_query($queryupdate);
		}
		# End
		# If Radio button for Cron Job type is pressed, call to action
		if (isset($_POST['cron'])) {
			$table = "tbladdonmodules";
			$where = array('module'=>'pricesautocalc','setting'=>'manualcron');
			switch ($_POST['cron']) {
				case "cronauto" :
					$update = array('value'=>FALSE);
					break;
				case "cronmanual" :
					$update = array('value'=>TRUE);
					break;
			}
			$test = $_POST['cron'];
			update_query($table,$update,$where);
		}
		# End
		# If UPDATE button was pressed, call to action
		if (isset($_POST['updateaction'])) {
			switch ($_POST['updateaction']) {
				case "Update Cron for Domains" :
				case "Actualizar Cron de Dominios" :
					if (isset($_POST['includeDomainsnotactive'])) {
						$queryupdate = "UPDATE `mod_pricesautocalc` SET `includenotactive`=1 WHERE `action`='domains' ";
						$resultupdate = full_query($queryupdate);
					} else {
						$queryupdate = "UPDATE `mod_pricesautocalc` SET `includenotactive`=0 WHERE `action`='domains' ";
						$resultupdate = full_query($queryupdate);
					}
					break;
				case "Update Cron for Products" :
				case "Actualizar Cron de Productos" :
					if (isset($_POST['includefree'])) {
						$queryupdate = "UPDATE `mod_pricesautocalc` SET `includefree`=1 WHERE `action`='products' ";
						$resultupdate = full_query($queryupdate);
					} else {
						$queryupdate = "UPDATE `mod_pricesautocalc` SET `includefree`=0 WHERE `action`='products' ";
						$resultupdate = full_query($queryupdate);
					}
					if (isset($_POST['includeProductsnotactive'])) {
						$queryupdate = "UPDATE `mod_pricesautocalc` SET `includenotactive`=1 WHERE `action`='products' ";
						$resultupdate = full_query($queryupdate);
					} else {
						$queryupdate = "UPDATE `mod_pricesautocalc` SET `includenotactive`=0 WHERE `action`='products' ";
						$resultupdate = full_query($queryupdate);
					}
					break;
			}
		}
		# End

		echo "<form action='addonmodules.php?module=pricesautocalc' method='post' role='form' id='form'>";

		# Config Cron Job
		echo "<div class='homewidget'><div class='widget-header'>".$LANG['pricesautocalc_showform_config_header']."</div>";
			# Get ManualCron Config
			$table = "tbladdonmodules";
			$fields = "value";
			$where = array("module"=>"pricesautocalc","setting"=>"manualcron");
			$result = select_query($table,$fields,$where);
			$data = mysql_fetch_array($result);
			# End Get ManualCron
			# JQuery to submit onchange
			echo "<script type='text/javascript'>
			$(document).ready(function() {
				$('input[name=cron]').change(function(){
					$('#form').submit();
					});
				});
			</script>";
			# End JQuery
		echo "<div class='widget-content'><div style='width:20%;float:left;'><input type='radio' name='cron' value='cronauto'";
		if (empty($data['value'])) { echo " checked"; }
		echo "> ".$LANG['pricesautocalc_showform_up_auto']."<br>";
		echo "<input type='radio' name='cron' value='cronmanual'";
		if (!empty($data['value'])) { echo " checked"; }
		echo "> ".$LANG['pricesautocalc_showform_up_man']."</div>";
		echo "<div style='width:80%;float:left;'><div class='infobox'><div style='padding:1%;'>";
		if (empty($data['value'])) {
			echo $LANG['pricesautocalc_showform_up_automesg'];
		} else {
			echo $LANG['pricesautocalc_showform_up_manmesg'];
			# Check if cron/path.php is configured
			require_once($addonpath."/cron/path.php");
			if ($fullpath == "" ) {
				echo "<p>".$LANG['pricesautocalc_showform_up_manmesgfile1'];
				echo "<input type='text' style='width:100%;' value='".$addonpath."/cron/path.php' onclick='this.select();'></p>";
				echo "<p>".$LANG['pricesautocalc_showform_up_manmesgfile2'];
				echo "<input type='text' style='width:100%;' value='\$fullpath=\"".$whmcspath."\"' onclick='this.select();'></p>";
				echo "<button class='btn btn-success' onclick='location.reload(true);'>".$LANG['pricesautocalc_showform_err_refresh']."</button>";
			} else {
				echo "<p>".$LANG['pricesautocalc_showform_up_manmesgcron1'];
				echo "<input type='text' style='width:100%;' value='php -q ".$addonpath."/cron/pricesautocalc_sync.php' onclick='this.select();'></p>";
			}
		}
		echo "</div></div></div></div></div>";

		# Central Notification System (CNS)
		echo "<div class='homewidget'><div class='widget-header'>".$LANG['pricesautocalc_showform_cns_header']."</div>";
		echo "<div class='widget-content'>";
		$whmcsurl = 'HTTPS://WWW.YOURDOMAIN.COM/';
		$notificationsfilepath = "/modules/addons/pricesautocalc/notes.txt";
		$notifications_remote = file_get_contents($whmcsurl.$notificationsfilepath);
		echo $notifications_remote;
		echo "</div></div>";

		# Update Cron Job
		echo "<div class='homewidget'><div class='widget-header'>".$LANG['pricesautocalc_showform_up_header']."</div>";
		echo "<div class='widget-content'><table class='form' border='0' cellpadding='3' cellspacing='2' width='100%'><tbody>";
			# Show buttons on form, based on current status
			$table = "mod_pricesautocalc";
			$fields = "action,activated,includefree,includenotactive";
			$result = select_query($table,$fields);
			# End
		while ($data = mysql_fetch_array($result)) {
			if ($data['activated'] == 1) {
				echo "<tr><td class='fieldlabel' width='20%'>".$LANG['pricesautocalc_showform_'.$data['action']]." <span class='label active'>".$LANG['pricesautocalc_showform_on']."</span></td>";
				echo "<td class='fieldarea'>";
				if (ucfirst($data['action']) == "Products") {
					echo "<input type='checkbox' name='includefree' value='includefree' ";
					if ($data['includefree'] == 1) {
						echo "checked";
					}
					echo "> ".$LANG['pricesautocalc_showform_inc'].$LANG['pricesautocalc_showform_freeprod']."<br/>";
				}
				echo "<input type='checkbox' name='include".ucfirst($data['action'])."notactive' value='include".ucfirst($data['action'])."notactive' ";
				if ($data['includenotactive'] == 1) {
					echo "checked";
				}
				echo "> ".$LANG['pricesautocalc_showform_inc'].$LANG['pricesautocalc_showform_exporcanc']."</td>";
				echo "<td class='fieldarea'><input type='submit' class='btn btn-success' name='updateaction' value='".$LANG['pricesautocalc_showform_up_update'].$LANG['pricesautocalc_showform_'.$data['action']]."'>";
				echo "</td>";
				echo "<td class='fieldarea' width='25%'><input type='submit' class='btn btn-danger' name='enableaction' value='".$LANG['pricesautocalc_showform_up_disab']." ".$LANG['pricesautocalc_showform_'.$data['action']]."'></td></tr>";
			} else {
				echo "<tr><td class='fieldlabel' width='20%'>".$LANG['pricesautocalc_showform_'.$data['action']]." <span class='label closed'>".$LANG['pricesautocalc_showform_off']."</span></td>";
				echo "<td class='fieldarea' colspan='3'><input type='submit' class='btn btn-success' name='enableaction' value='".$LANG['pricesautocalc_showform_up_enab']." ".$LANG['pricesautocalc_showform_'.$data['action']]."'></td></tr>";
			}
		}
		echo "</tbody></table></div></div>";
		# End

		# Force Manual Update
		# Domains
		echo "<div class='homewidget'>";
		echo "<div class='widget-header'>".$LANG['pricesautocalc_showform_f_header']."</div>";
		echo "<div class='widget-content'><table class='form' border='0' cellpadding='3' cellspacing='2' width='100%'><tbody>";
		echo "<tr><td class='fieldlabel' width='20%'>".$LANG['pricesautocalc_showform_f_force']." AutoCalc".$LANG['pricesautocalc_showform_domains']."</td>";
		echo "<td class='fieldarea'>";
		echo "<input type='checkbox' name='forcedomainnotactive' value='forcedomainnotactive'";
		if (isset($_POST['forcedomainnotactive'])) { echo "checked"; }
		echo "> ".$LANG['pricesautocalc_showform_inc'].$LANG['pricesautocalc_showform_exporcanc']."</td>";
		echo "<td class='fieldarea'>";
		echo "<input type='checkbox' name='forcedomainshowresult' value='forcedomainshowresult'";
		if (isset($_POST['forcedomainshowresult'])) { echo "checked"; }
		echo ">".$LANG['pricesautocalc_showform_f_show']."</td>";
		echo "<td class='fieldarea' width='25%'><input type='submit' class='btn btn-warning' name='forceaction' value='".$LANG['pricesautocalc_showform_f_force'].$LANG['pricesautocalc_showform_domains']."'></td></tr>";
		# Products
		echo "<tr><td class='fieldlabel'>".$LANG['pricesautocalc_showform_f_force']." AutoCalc".$LANG['pricesautocalc_showform_products']."</td>";
		echo "<td class='fieldarea'>";
		echo "<input type='checkbox' name='forcefree' value='forcefree'";
		if (isset($_POST['forcefree'])) { echo "checked"; }
		echo "> ".$LANG['pricesautocalc_showform_inc'].$LANG['pricesautocalc_showform_freeprod']."<br/>";
		echo "<input type='checkbox' name='forceproductnotactive' value='forceproductnotactive'";
		if (isset($_POST['forceproductnotactive'])) { echo "checked"; }
		echo "> ".$LANG['pricesautocalc_showform_inc'].$LANG['pricesautocalc_showform_exporcanc']."</td>";
		echo "<td class='fieldarea'>";
		echo "<input type='checkbox' name='forceproductshowresult' value='forceproductshowresult'";
		if (isset($_POST['forceproductshowresult'])) { echo "checked"; }
		echo ">".$LANG['pricesautocalc_showform_f_show']."</td>";
		echo "<td class='fieldarea' width='25%'><input type='submit' class='btn btn-warning' name='forceaction' value='".$LANG['pricesautocalc_showform_f_force'].$LANG['pricesautocalc_showform_products']."'></td></tr>";
		echo "</tbody></table></div></div></form>";
		# End
		# If a FORCE button was pressed, call to action
		if (isset($_POST['forceaction'])) {
			switch ($_POST['forceaction']) {
				case "Force Domains" :
				case "Forzar Dominios" :
					$command = "updateclientdomain";
					$adminuser = $apiadminuser;
					$valuesdomains = array();
					$values["autorecalc"] = true;
					# Create SQL Query for Domains
					$table = "tbldomains";
					$fields = "id, domain, userid, promoid";
					$where = array();
					if (!isset($_POST['forcedomainnotactive'])) {
						$where["status"] = "Active";
					}
					# End
					# Get List of Domains
					$resultDomains = select_query($table,$fields,$where);
					# End
					# Iterate Domains and Autorecalc
					echo "<div class='homewidget'>";
					echo "<div class='widget-header'>".$LANG['pricesautocalc_showform_r_header']."</div>";
					echo "<div class='widget-content'><table class='form' border='0' cellpadding='3' cellspacing='2' width='100%'><tbody>";
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
						if (isset($_POST['forcedomainshowresult'])) {
							echo "<tr><td class='fieldlabel' width='20%'>".$dataDomains['domain']."</td><td class='fieldarea'><pre>".htmlspecialchars(print_r($results,true))."</pre></td></tr>";
							}
						}
					# End
					if (!isset($_POST['forcedomainshowresult'])) {
						echo "<tr><td>".$LANG["pricesautocalc_showform_r_nothing"]."</td></tr>";
						}
					echo "</tbody></table></div></div>";
					logModuleCall("pricesautocalc","manual_update",$command,$valuesdomains);
					break;
				case "Force Products" :
				case "Forzar Productos" :
					$command = "updateclientproduct";
					$adminuser = $apiadminuser;
					$valuesproducts = array();
					$values["autorecalc"] = "1";
					# Create SQL Query
					$table = "tblhosting";
					$fields = "id, domain";
					$where = array();
					if (!isset($_POST['forcefree'])) {
						$where["billingcycle"] = array("sqltype"=>"NEQ","value"=>"Free Account");
						}
					if (!isset($_POST['forceproductnotactive'])) {
						$where["domainstatus"] = "Active";
						}
					# End
					# Get List of Products
					$resultProducts = select_query($table,$fields,$where);
					# End
					# Iterate Products and Autorecalc
					echo "<div class='homewidget'>";
					echo "<div class='widget-header'>Manual Update for Products</div>";
					echo "<div class='widget-content'><table class='form' border='0' cellpadding='3' cellspacing='2' width='100%'><tbody>";
					while ($dataProducts = mysql_fetch_array($resultProducts)) {
						$values["serviceid"] = $dataProducts['id'];
						$values["domain"] = $dataProducts['domain'];
						$results = localAPI($command,$values,$adminuser);
						$valuesproducts[$values["domain"]] = $results;
						if (isset($_POST['forceproductshowresult'])) {
							echo "<tr><td class='fieldlabel' width='20%'>".$values["domain"]."</td><td class='fieldarea'><pre>".htmlspecialchars(print_r($results,true))."</pre></td></tr>";
							}
						}
					# End
					if (!isset($_POST['forceproductshowresult'])) {
						echo "<tr><td>".$LANG["pricesautocalc_showform_r_nothing"]."</td></tr>";
						}
					echo "</tbody></table></div></div>";
					logModuleCall("pricesautocalc","manual_update",$command,$valuesproducts);
					break;
			}
			$resultupdate = full_query($queryupdate);
		}
		# End
	}
}

function pricesautocalc_sidebar($vars) {
	$modulelink = $vars['modulelink'];
	$version = $vars['version'];
	$LANG = $vars['_lang'];
	# Check for update
	$whmcsurl = 'HTTPS://WWW.YOURDOMAIN.COM/';
	$upgradefilepath = "/modules/addons/pricesautocalc/version.txt";
	$version_remote = file_get_contents($whmcsurl.$upgradefilepath);
	# End check for update
	$sidebar = "<span class='plain_header'>Prices AutoCalc</span>\n".$LANG['pricesautocalc_sidebar_pl']."<br/>".$LANG['pricesautocalc_sidebar_v']." : ".$version."<br/>";
	if ($version<$version_remote){
		$checkupdate = "<input class='btn btn-danger' value='".$LANG['pricesautocalc_sidebar_ua'].$version_remote."' onClick=\"window.open('".$whmcsurl."clientarea.php?action=products')\"/><br/><br/><br/>";
	} else {
		$checkupdate = "<span class='label active'>".$LANG['pricesautocalc_sidebar_u']."</span><br/><br/><br/>";
	}
	$sidebar = $sidebar.$checkupdate;
	return $sidebar;
}
?>
