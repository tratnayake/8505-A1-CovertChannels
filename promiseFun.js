'use strict'

var promiseCount = 0;
console.log("Test")

function checkMessageLength(message){
	return new Promise(function(resolve,reject){
		console.log("Inside promise message is: " + message);
		resolve("Promise worked!");
	})
}

checkMessageLength("Test")
.then(function(value){
	console.log(value);
})
.catch(
	function(reason){
		console.log(reason);
	}
)