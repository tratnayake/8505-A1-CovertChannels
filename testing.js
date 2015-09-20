
//Require the socket.

var raw = require ("raw-socket");

var options = {
	protocol: raw.Protocol.ICMP
};

var socket = raw.createSocket (options);

var target = process.argv[2];

var MTU = 50;

var messageToSend

//1. Create buffer with only everything until data section
	console.log("Stage 1. Creating buffers")
	console.log("Start buffer, populate with usual info");
	var buffer = new Buffer(40);

	buffer.write('0800000000010a09',0,'hex');

	


	var buffer1 = new Buffer ([
	 		0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x09 ]);

	console.log("Buffer length " + buffer.length);
	console.log(buffer.toString('hex'));
	console.log("Buffer 1 length "+ buffer1.length);
	console.log(buffer1.toString('hex'));

//2. Add some data to the packet
	console.log("\n\nStage 2. Adding data to packets");
	buffer.write("abcdefghijklmnopqrstuvwabcdefghi",8,32,'ascii');
	var buffer1 = new Buffer ([
	 		0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x09,
	 		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
	 		0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
	 		0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61,
	 		0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69]);

	console.log("Buffer length " + buffer.length);
	console.log(buffer.toString('hex'));
	console.log("Buffer 1 length "+ buffer.length);
	console.log(buffer1.toString('hex'));

	var string1 = buffer.toString('hex');
	var string2 = buffer1.toString('hex');
	console.log(string1);
	console.log(string2);
	console.log(buffer.equals(buffer1));
	console.log("Data addition comparison check PASSED!");

//3. Perform the checksum calculation
	console.log("\n\nStage 3. Checksum Calculation");
	raw.writeChecksum (buffer, 2, raw.createChecksum (buffer));
	raw.writeChecksum (buffer1, 2, raw.createChecksum (buffer1));
	var string1 = buffer.toString('hex');
	var string2 = buffer1.toString('hex');
	console.log(string1);
	console.log(string2);
	console.log(buffer.equals(buffer1));
	console.log("Checksum calculation comparison check PASSED!");


	
	socket.send (buffer, 0, buffer.length, target, function (error, bytes) {
		if (error) {
			console.log (error.toString ());
		} else {
			console.log ("sent " + bytes + " bytes to " + target);
		}
	});
	






























// buf = new Buffer(256);
// len = buf.write('\u00bd + \u00bc = \u00be', 0);
// console.log(len + " bytes: " + buf.toString('utf8', 0, len));


// var raw = require ("raw-socket");

// var buf = new Buffer('test');
// console.log(buf.toString('hex'));
// var json = JSON.stringify(buf);

// console.log(json);
// // '{"type":"Buffer","data":[116,101,115,116]}'

// var copy = JSON.parse(json, function(key, value) {
//     return value && value.type === 'Buffer'
//       ? new Buffer(value.data)
//       : value;
//   });

// console.log(copy);