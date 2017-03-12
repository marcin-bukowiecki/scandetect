angular
	.module("app.startMonitoringPorts")
	.config(function ($routeProvider) {

		$routeProvider
			.when("/", {
				templateUrl: 'assets/html/home.html'
			})
			.when("/analyzedPackets", {
				templateUrl: 'assets/html/captured-packets.html'
			})
			.when("/settings", {
				templateUrl: 'assets/html/settings.html'
			})
			.when("/showAlerts", {
				templateUrl: 'assets/html/alerts.html',
			});
	});