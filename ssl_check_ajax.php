<?php
$hostname = $_POST["domain"];
$ssloptions = array(
    "capture_peer_cert_chain" => true, 
    "allow_self_signed"=>false, 
    "CN_match"=>$hostname, 
    "verify_peer"=>true, 
    "SNI_enabled"=>true,
    "SNI_server_name"=>$hostname,
);
$certs = array();
$ctx = stream_context_create( array("ssl" => $ssloptions) );
$result = @stream_socket_client("ssl://$hostname:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $ctx);
if(!$result)
{
	$bad_ssl = array(
			    'Common name'			=> 'BadSSL',
			    'SANs'					=> '-',
			    'Valid'					=> '01/01/1970 - 01/01/1970',
			    'Serial Number'			=> 'No Serial',
			    'Signature Algorithm'	=> 'No Crytpo',
			    'Issuer'				=> 'Bad Issuer',
			    'image'					=> 'certificate_bad_server.png',
		    ); 
	array_push($certs, $bad_ssl);
}else
{
	$cont = stream_context_get_params($result);
	foreach($cont["options"]["ssl"]["peer_certificate_chain"] as $cert)
	{
	    openssl_x509_export($cert, $pem_encoded);
	    $certinfo = openssl_x509_parse($pem_encoded);
	
	    if(array_key_exists('subjectAltName', $certinfo["extensions"]))
	    {
		    $common_name = $certinfo["subject"]["CN"];
		    $algorithm = $certinfo["signatureTypeLN"];
			$issuer = $certinfo["issuer"]["CN"];
		    $start_date = trDate($certinfo["validFrom_time_t"]);
		    $end_date = trDate($certinfo["validTo_time_t"]);
		    $sans = trim(str_replace('DNS:', '', $certinfo["extensions"]["subjectAltName"]));
		    $serial = $certinfo["serialNumber"];	   
		    $c1 = array(
			    'Common name'			=> $common_name,
			    'SANs'					=> $sans,
			    'Valid'					=> ''.$start_date.' - '.$end_date.'',
			    'Serial Number'			=> $serial,
			    'Signature Algorithm'	=> $algorithm,
			    'Issuer'				=> $issuer,
			    'image'					=> 'certificate_good_server.png',
		    ); 
		    array_push($certs, $c1);
	
	
	    }else
	    {
		    if(array_key_exists('L', $certinfo["subject"]) && array_key_exists('ST', $certinfo["subject"]))
		    {
				$location = ''.$certinfo["subject"]["L"].', '.$certinfo["subject"]["ST"].', '.$certinfo["subject"]["C"].'';
	
		    }else
		    {
			    $location = ''.$certinfo["subject"]["C"].'';
		    }
		    
			$start_date = trDate($certinfo["validFrom_time_t"]);
		    $end_date = trDate($certinfo["validTo_time_t"]);
		    $serial = $certinfo["serialNumber"];	  
			$algorithm = $certinfo["signatureTypeLN"];
			$issuer = $certinfo["issuer"]["CN"];
		    $c2 = array(
			    'Common name'			=> $certinfo["subject"]["CN"],
			    'Organization'			=> $certinfo["subject"]["O"],
			    'Location'				=> $location,
			    'Valid'					=> ''.$start_date.' - '.$end_date.'',
			    'Serial Number'			=> $serial,
			    'Signature Algorithm'	=> $algorithm,
			    'Issuer'				=> $issuer,
			    'image'					=> 'certificate_good_chain.png',
		    );
		    array_push($certs, $c2);
	    }
	}
}

function trDate($time)
{
	setlocale(LC_TIME,'turkish');
	return iconv('latin5','utf-8',strftime(' %d %B %Y %A %H:%M:%S',$time));
}

?>
<table class="checker_certs">
	<tbody>
			

<?php
	$i = 0;
foreach($certs as $v )
{

?>
		<tr>
			<td class="cert">
				<img src="img/<?=$v["image"]?>" height="128" width="128">
				</td>
			<td>
				<?php
					foreach($v as $k=>$z)
					{
						if($k != "image")
						{
							echo '<b>'.$k.':</b>';
							echo ''.$z.'<br>';
						}
						
					}
					?>
				</td>
			<td></td>
		</tr>
		<?php
			if($i < count($certs) -1)
			{
			?>
		<tr><td class="chain"><center><img src="img/arrow_down.png" height="48" width="48"></center></td><td>&nbsp;</td></tr>

<?php
	}
	$i = $i+1;
}
?>
</tbody>
</table>
