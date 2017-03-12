(function() {
	'use strict';

	angular.module("app.startMonitoringPorts").factory("CollapseTabComponent",
			CollapseTabComponent);

	function CollapseTabComponent() {
		return React.createClass({
			render : function() {
				var viewController = this.props;

				if (this.props.alerts.length == 0) return React.DOM.div(null, "No alerts");

				return React.DOM.div(
					{ className: "alerts-tab" },
					this.props.alerts.map(function(row, idx) {
						var numberOfScannedPorts = row.scannedPorts.length;
						var limit = 30;
						if (numberOfScannedPorts < 30) {
							limit = numberOfScannedPorts;
						}
						return [React.DOM.button(
							{ className: "btn btn-primary", type: "button", "data-toggle": "collapse", "data-target": "#collapseAlertsTab" + idx, aria: {expanded: "false", controls: "collapseAlertsTab"}  },
							row.scanType + " attack from: " + row.ipAttacker + ", at: " + row.time + ", chance: " + row.chance + "%"
						),
							React.DOM.br(null, null),
							React.DOM.div(
								{className: "collapse", id: "collapseAlertsTab" + idx},
								React.DOM.div(
									{className: "well"},
									[
										"Used software: " + row.softwareUsed.map(function(s) {
											return s;
										}) + ".",
										React.DOM.br(null, null),
										"Used technique: " + row.attackType + ".",
										React.DOM.br(null, null),
										"Scanned ports (Limited list to 30): " + row.scannedPorts.slice(0,limit).map(function(s) {
											return s;
										}) + ".",
										React.DOM.br(null, null),
										"Scanned number of ports: " + row.scannedPorts.length,
										React.DOM.br(null, null),
										React.DOM.button(
											{ className: "btn btn-danger", "onClick":  function(){
												viewController.removeAlert(row.scanType, row.attackType, row.ipAttacker);
											} },
											"Remove alert"
										)
									]
								)
							)
						];
					})
				);
			}
		});
	}

})();