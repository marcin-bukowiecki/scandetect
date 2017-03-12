(function() {
    'use strict';

    angular
        .module("app.startMonitoringPorts")
        .service("startMonitoringPortsService", startMonitoringPortsService);

    function startMonitoringPortsService($http) {
        var vm = this;

        vm.startMonitoring = startMonitoring;
        vm.getNetworkInterfaces = getNetworkInterfaces;
        vm.checkIfIsRunning = checkIfIsRunning;
        vm.stopMonitoringPorts = stopMonitoringPorts;
        vm.getCapturedPackets = getCapturedPackets;
        vm.getNumberOfPages = getNumberOfPages;
        vm.removeAllPackets = removeAllPackets;
        vm.getAlerts = getAlerts;

        function startMonitoring(vm, ignoredIps, networkInterface, runAsHoneypot) {
            $http({
            	method: 'POST',
            	url: 'startMonitoringPorts',
            	data: {ignoredIps: ignoredIps, networkInterface: networkInterface, runAsHoneypot: runAsHoneypot}
            }).then(function successCallback(response) {
            	checkIfIsRunning(vm);
            	$('#start-monitoring-modal').modal('hide');
            }, function errorCallback(response) {
                console.log(response);
                return [];
            });
        };

        function getNetworkInterfaces(vm) {
            $http({
                method: 'GET',
                url: 'getNetworkInterfaces'
            }).then(function successCallback(response) {
                console.log(response);
                response.data.unshift({name: "", description: "", addresses: []})
                vm.networkInterfaces = response.data;
                return response.data;
            }, function errorCallback(response) {
                console.log(response);
                return [];
            });
        };
        
        function checkIfIsRunning(vm) {
        	$http({
                method: 'POST',
                url: 'isRunning'
            }).then(function successCallback(response) {
            	if (response.data == true) {
            		vm.isRunning = true;
            	} else {
            		vm.isRunning = false;
            	}
            }, function errorCallback(response) {
                console.log(response);
                vm.isRunning = false;
            });
        }
        
        function stopMonitoringPorts(vm) {
        	$http({
                method: 'POST',
                url: 'stopMonitoringPorts'
            }).then(function successCallback(response) {
            	checkIfIsRunning(vm);
            });
        }
        
        function getCapturedPackets(vm) {
        	$http({
                method: 'POST',
                url: 'getCapturedPackets',
                data: { protocol: vm.filter.protocol, destinationAddress: vm.filter.destinationAddress, destinationPort: vm.filter.destinationPort, sourceAddress: vm.filter.sourceAddress, sourcePort: vm.filter.sourcePort, currentPage: vm.filter.currentPage, numberOfPages: vm.filter.numberOfPages }
            }).then(function successCallback(response) {
            	vm.capturedPackets = response.data.packets;
            	vm.filter.numberOfPages = Math.ceil(response.data.numberOfPackets / 20);
                vm.disablePageInput = false;
            });
        }
        
        function getNumberOfPages(vm) {
        	$http({
                method: 'POST',
                url: 'getNumberOfPages',
                data: { protocol: vm.filter.protocol, destinationAddress: vm.filter.destinationAddress, destinationPort: vm.filter.destinationPort, sourceAddress: vm.filter.sourceAddress, sourcePort: vm.filter.sourcePort, currentPage: vm.filter.currentPage, numberOfPages: vm.filter.numberOfPages }
            }).then(function successCallback(response) {
            	vm.filter.numberOfPages = response.data;
            	vm.disablePageInput = false;
            });
        }
        
        function removeAllPackets(vm) {
        	var confirmed = confirm("Do you want to remove all captured packets?");
        	
        	if (confirmed) {
            	$http({
            		method: 'DELETE',
            		url: 'removeAllPackets'
            	}).then(function successCallback(response) {
            		vm.capturedPackets = [];
                    vm.analyzedPacketsNumber = 0;
                    vm.capturedPacketsNumber = 0;
            		vm.filter.numberOfPages = 1;
            		vm.filter.currentPage = 1;
                }); 
        	}
        }

        function getAlerts(vm) {
            $http({
                method: 'GET',
                url: 'getAlerts'
            }).then(function successCallback(response) {
                vm.alerts = response.data;
            });
        }

    };

})();