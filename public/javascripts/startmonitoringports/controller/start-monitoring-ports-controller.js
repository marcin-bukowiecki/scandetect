(function() {
    'use strict';

    angular
        .module('app.startMonitoringPorts')
        .controller('startMonitoringPortsController', startMonitoringPortsController);

    function startMonitoringPortsController($http, $interval, $websocket, $timeout, startMonitoringPortsService) {
        var vm = this;
        vm.test = "startMonitoringPortsController";

        vm.selectedNetworkInterface = {
            name: "",
            addresses: [],
            description: ""
        };
        
        vm.filter = {
        	time: "",
        	protocol: "",
        	sourceAddress: "",
        	sourcePort: "",
        	destinationAddress: "",
        	destinationPort: "",
        	currentPage: 1,
        	numberOfPages: 1,
            length: "",
        };
        vm.capturedPackets = [{time: "1234", protocol: "TCP", sourceAddress: "123.12.12.1", sourcePort: "192.168.1.1", destinationAddress: "443", destinationPort: "8080", length: "80", info: "to jest info", flags: []}];
        vm.ignoredIP = "";
        vm.savedSettings = false;
        vm.isRunning = false;
        vm.disablePageInput = true;
        vm.networkInterfaces = [];
        vm.analyzedPacketsNumber = 0;
        vm.capturedPacketsNumber = 0;
        vm.connectedToDatabase = false;
        vm.settings = {
          databaseUrl: "localhost:27017/test",
            databaseUsername: "",
            databasePassword: "",
           closedPortThreshold: 5,
           useHoneypot: false,
           honeypotDatabaseUrl: "",
           honeypotDatabaseUsername: "",
           honeypotDatabasePassword: ""
        };
        vm.startMonitoring = startMonitoring;
        vm.getNetworkInterfaces = getNetworkInterfaces;
        vm.setSelectedNetworkInterface = setSelectedNetworkInterface;
        vm.addIgnoredIP = addIgnoredIP;
        vm.cancelStartMonitoring = cancelStartMonitoring;
        vm.validateStartMonitoring = validateStartMonitoring;
        vm.checkIfIsRunning = checkIfIsRunning;
        vm.networkInterfaceSelected = networkInterfaceSelected;
        vm.stopMonitoringPorts = stopMonitoringPorts;
        vm.getCapturedPackets = getCapturedPackets;
        vm.getNumberOfPages = getNumberOfPages;
        vm.previousPage = previousPage;
        vm.nextPage = nextPage;
        vm.pageNumberChanged = pageNumberChanged;
        vm.removeAllPackets = removeAllPackets;
        vm.isDatabaseAvailable = isDatabaseAvailable;
        vm.getCapturedPacketsCount = getCapturedPacketsCount;
        vm.getAnalyzedPacketsCount = getAnalyzedPacketsCount;
        vm.saveSettings = saveSettings;
        vm.loadSettings = loadSettings;
        vm.clearHistory = clearHistory;
        vm.connectToDatabase = connectToDatabase;
        vm.runAsHoneypot = false

        //to alerts
        vm.alerts = [];
        vm.getAlerts = getAlerts;
        vm.removeAlert = removeAlert;

        checkIfIsRunning();

        function init() {
            isDatabaseAvailable();
            getCapturedPacketsCount();
            getAnalyzedPacketsCount();

             var dataStream = $websocket('ws://localhost:9000/callLoading');

            dataStream.onMessage(function(message) {
                console.log(message.data);
                var parsed = JSON.parse(message.data);
                setStatistics(parsed);
            });

            dataStream.onOpen(function(e) {

            });

            dataStream.onClose(function(e) {

            });

            dataStream.onError(function(e) {

            });

            function sendMessage() {
                dataStream.send(JSON.stringify({
                    command: "getStats"
                    }
                ));
            }

            setInterval(sendMessage, 5000);
        }

        init();

        function getNetworkInterfaces() {
            startMonitoringPortsService.getNetworkInterfaces(vm);
        }

        function setSelectedNetworkInterface() {
            vm.networkInterfaces.forEach(function (row) {
               if (row.name === $("#network-interfaces-select").val()) {
                   vm.selectedNetworkInterface.description = row.description;
                   vm.selectedNetworkInterface.name = row.name;
                   vm.selectedNetworkInterface.addresses = row.addresses;
               }
            });
        }

        function addIgnoredIP() {
            if (vm.ignoredIP !== undefined && vm.ignoredIP !== "") {
                $('#ignoredIpsInput').tagsinput('add', vm.ignoredIP);
                vm.ignoredIP = "";
            }
        }

        function validateStartMonitoring() {

        }

        function cancelStartMonitoring() {
            vm.ignoredIP = "";
            $('#ignoredIpsInput').tagsinput('removeAll');
            $("#network-interfaces-select").val("");
            vm.selectedNetworkInterface = {
                name: "",
                addresses: [],
                description: ""
            };
        }
        
        function startMonitoring() {
        	var ignoredIps = $("#ignoredIpsInput").tagsinput('items');
        	var networkInterface = $('#network-interfaces-select').val();
        	startMonitoringPortsService.startMonitoring(vm, ignoredIps, networkInterface, vm.runAsHoneypot);
        }
        
        function checkIfIsRunning() {
        	vm.isRunning = startMonitoringPortsService.checkIfIsRunning(vm);
        }
        
        function stopMonitoringPorts() {
        	startMonitoringPortsService.stopMonitoringPorts(vm);
        }
        
        function getCapturedPackets() {
        	vm.disablePageInput = true;
        	startMonitoringPortsService.getCapturedPackets(vm);
        }
        
        function getNumberOfPages() {
        	vm.disablePageInput = true;
        	startMonitoringPortsService.getNumberOfPages(vm);
        }

        function previousPage() {
        	if (vm.filter.currentPage > 1) {
        		vm.disablePageInput = true;
        		vm.filter.currentPage--;
        		pageNumberChanged();
        	}
        }
        
        function nextPage() {
        	if (vm.filter.currentPage < vm.filter.numberOfPages) {
        		vm.disablePageInput = true;
        		vm.filter.currentPage++;
        		pageNumberChanged();
        	}
        }
        
        function pageNumberChanged() {
        	if (!isNaN(parseInt(vm.filter.currentPage)) && vm.filter.currentPage >= 1 && vm.filter.currentPage <= vm.filter.numberOfPages) {
        		vm.disablePageInput = true;
            	startMonitoringPortsService.getCapturedPackets(vm);
        	} else {
                vm.disablePageInput = false;
            }
        }
        
        function removeAllPackets() {
        	startMonitoringPortsService.removeAllPackets(vm);
        }

        function getAlerts() {
            startMonitoringPortsService.getAlerts(vm);
        }

        //$interval(isDatabaseAvailable, 10000)
       // $interval(getCapturedPacketsCount, 10000);
        //$interval(getAnalyzedPacketsCount, 10000);

        function isDatabaseAvailable() {
            $http({
                method: 'POST',
                url: 'isDatabaseAvailable',
            }).then(function successCallback(response) {
                vm.connectedToDatabase = response.data;
            }, function errorCallback(e) {
               vm.connectedToDatabase = false;
            });
        }

        function getCapturedPacketsCount() {
            /*
            $http({
                method: 'GET',
                url: 'getCapturedPacketsCount',
            }).then(function successCallback(response) {
                vm.capturedPacketsNumber = response.data;
            });*/
        }

        function getAnalyzedPacketsCount() {
            /*
            $http({
                method: 'GET',
                url: 'getAnalyzedPacketsCount',
            }).then(function successCallback(response) {
                vm.analyzedPacketsNumber = response.data;
            });*/
        }

        function saveSettings() {
            $http({
                method: "POST",
                url: "saveSettings",
                data: {databaseUrl: vm.settings.databaseUrl, closedPortThreshold: vm.settings.closedPortThreshold,
                    useHoneypot: vm.settings.useHoneypot, honeypotDatabaseUrl: vm.settings.honeypotDatabaseUrl,
                    honeypotDatabaseUsername: vm.settings.honeypotDatabaseUsername, honeypotDatabasePassword: vm.settings.honeypotDatabasePassword,
                databaseUsername: vm.settings.databaseUsername, databasePassword: vm.settings.databasePassword
                }
            }).then(function successCallback(response) {
                vm.savedSettings = true;
                $timeout(function () {
                    vm.savedSettings = false;
                }, 5000);
            }, function errorCallback(e) {
                alert("Settings not saved. maybe database is still down?");
            });
        }

        function loadSettings() {
            $http({
                method: 'GET',
                url: 'loadSettings'
            }).then(function successCallback(response) {
                response.data.forEach(function(row) {
                    if (row.key === "DATABASE_URL") {
                        vm.settings.databaseUrl = row.value;
                    }
                    if (row.key === "CLOSED_PORT_THRESHOLD") {
                        vm.settings.closedPortThreshold = parseInt(row.value);
                    }
                    if (row.key === "USE_HONEYPOT") {
                        vm.settings.useHoneypot = (row.value === 'true');
                    }
                    if (row.key === "HONEYPOT_DATABASE_URL") {
                        vm.settings.honeypotDatabaseUrl = row.value;
                    }
                });

            });
        }

        function networkInterfaceSelected() {
            return $('#network-interfaces-select').val() !== "";
        }

        function clearHistory() {
            var confirmed = confirm("Are you sure you want to remove whole history?");

            if (confirmed) {
                $http({
                    method: 'GET',
                    url: 'clearHistory'
                });
            }
        }

        function connectToDatabase() {
            $http({
                method: 'GET',
                url: 'connectToDatabase'
            });
        }

        function removeAlert(scanType, attackType, ipAttacker) {
            var confirmed = confirm("Are you sure you want to remove this alert?");

            if (confirmed) {
                $http({
                    method: 'POST',
                    url: 'removeAlert',
                    data: {scanType: scanType, ipAttacker: ipAttacker, attackType: attackType}
                }).then(function successCallback(response) {
                    getAlerts();
                });
            }
        }

        function setStatistics(jsonData) {
            vm.analyzedPacketsNumber = jsonData.numberOfAnalyzedPackets;
            vm.capturedPacketsNumber = jsonData.numberOfCapturedPackets;
        }
    };

})();
