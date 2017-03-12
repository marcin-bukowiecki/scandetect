$(document).ready(function() {
    $("#loading").on('click', function() {

        var url = "/callLoading";

        var ws = new WebSocket("ws://localhost:9000/callLoading");

        ws.onmessage = function(event) {
            console.log(event.data);
        };

        ws.onopen = function(event) {
            console.log("opening");
            ws.send("test");
        };

        ws.onclose = function(event) {
            console.log("closed");
        };

        ws.onerror = function(event) {
            console.log("error");
        };

        function sendMessage() {
            ws.send("test");
        }

        setInterval(sendMessage, 5000);
    });
});