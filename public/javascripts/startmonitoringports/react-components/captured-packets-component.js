(function() {
	'use strict';

	angular.module("app.startMonitoringPorts")
		.factory("CapturedPacketsTable", CapturedPacketsTable)
		.factory("AnalyzedPacketsNumberSpan", AnalyzedPacketsNumberSpan)
		.factory("ConnectionWithDatabase", ConnectionWithDatabase)
		.factory("CapturedPacketsNumberSpan", CapturedPacketsNumberSpan);

	function CapturedPacketsTable() {
		return React.createClass({
			render : function() {
				var viewController = this.props;
				return React.DOM.table({
					className : "table table-striped captured-packets-table"
				}, [
						React.DOM.thead(null, [ React.DOM.tr(null, [
								React.DOM.th(null, "Time"),
								React.DOM.th(null, "Protocol"),
								React.DOM.th(null, "Source address"),
								React.DOM.th(null, "Source port"),
								React.DOM.th(null, "Destination address"),
								React.DOM.th(null, "Destination port"),
								React.DOM.th(null, "Length"),
								React.DOM.th(null, "Info"), ]) ]),
						React.DOM.tbody(null, this.props.capturedPackets
								.map(function(row) {
									return React.DOM.tr(null, [
											React.DOM.td(null, row.time),
											React.DOM.td(null, row.protocol),
											React.DOM.td(null,
													row.sourceAddress),
											React.DOM.td(null, row.sourcePort),
											React.DOM.td(null,
													row.destinationAddress),
											React.DOM.td(null,
													row.destinationPort),
											React.DOM.td(null, row.length),
											React.DOM.td(null, row.protocol == "TCP" ? createPacketInfo(row.flags, row.info) : "")
									])
								})) ])
			}
		});
	}

	function CapturedPacketsNumberSpan() {
		return React.createClass({
			render: function () {
				var viewController = this.props;
				return React.DOM.span(
					{className: "label label-default"},
					"Captured packets: " + viewController.capturedPacketsNumber
				);
			}
		});
	}

	function AnalyzedPacketsNumberSpan() {
		return React.createClass({
			render: function () {
				var viewController = this.props.analyzedPacketsNumber;
				return React.DOM.span(
					{className: "label label-default"},
					"Analyzed packets: " + this.props.analyzedPacketsNumber
				);
			}
		});
	}

	function ConnectionWithDatabase() {
		return React.createClass({
			render: function () {
				var viewController = this.props;
				if (viewController.connectedToDatabase == true) {
					return React.DOM.span(
						{className: "label label-success"},
						"Connection with database OK"
					);
				} else {
					return React.DOM.span(
						{className: "label label-danger"},
						"No connection with database!!!"
					);
				}
			}
		});
	}

	function createPacketInfo(flags, info) {
		var flags = "Flags=" + flags.map(function(row) {
			return row + " ";
		});

		return flags + "WIN SCALE=" + info.WIN_SCALE + " WIN=" + info.WIN + " SEQ=" + info.SEQ + " HEADER LENGTH=" + info.HEADER_LENGTH;
	}

})();