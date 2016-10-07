# TTLOutboundFilter
This simple tool is a different way to determine outbound filtering rule without an outside miror.
http://www.shelliscoming.com/2014/11/getting-outbound-filtering-rules-by.html
"The idea is to launch a TCP connection to a public IP (this IP does not need to be under your control) with a low TTL value" -  Borja Merino 
Based on his ruby version : https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/recon/outbound_ports.rb
