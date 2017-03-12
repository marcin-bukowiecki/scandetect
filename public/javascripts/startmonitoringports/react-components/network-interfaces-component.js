(function() {
    'use strict';

    angular
        .module("app.startMonitoringPorts")
        .factory("NetworkInterfacesComponent", NetworkInterfacesComponent)
        .factory("SelectedNetworkInterfacesComponent", SelectedNetworkInterfacesComponent);

    function NetworkInterfacesComponent() {
        return React.createClass({
           render: function() {
               var viewController = this.props;
               return React.DOM.div(
                   null,
                   [
                       React.DOM.label({htmlFor: "network-interfaces-select"}, "Network interface:"),
                       React.DOM.select(
                           { className: "form-control", id: "network-interfaces-select", onChange: function() {
                               viewController.setSelectedNetworkInterface();
                           }},
                           this.props.networkInterfaces.map(function(row) {
                               return React.DOM.option({value: row.name}, row.name)
                           })
                       )
                   ]
               )
           }
        });
    }

    function SelectedNetworkInterfacesComponent() {
        return React.createClass({
            render: function() {
                if (this.props.selectedNetworkInterface.addresses.length !== 0) {
                    var ipV4Address = {
                        address: this.props.selectedNetworkInterface.addresses[0].address,
                        broadcast: this.props.selectedNetworkInterface.addresses[0].broadcast
                    };
                    var ipV6Address = {
                        address: this.props.selectedNetworkInterface.addresses[1].address,
                        broadcast: this.props.selectedNetworkInterface.addresses[1].broadcast
                    };
                    return React.DOM.div(
                        null,
                        [
                            React.DOM.span(null, React.DOM.label({}, "Name:")),
                            React.DOM.br(null, null),
                            React.DOM.span(null, this.props.selectedNetworkInterface.name),
                            React.DOM.br(null, null),
                            React.DOM.br(null, null),
                            React.DOM.span(null, React.DOM.label({}, "Description:")),
                            React.DOM.br(null, null),
                            React.DOM.span(null, this.props.selectedNetworkInterface.description),
                            React.DOM.br(null, null),
                            React.DOM.br(null, null),
                            React.DOM.span(null, React.DOM.label({}, "IPv4 address:")),
                            React.DOM.br(null, null),
                            React.DOM.span(null, ipV4Address.address),
                            /*React.DOM.br(null, null),
                            React.DOM.span(null, ipV4Address.broadcast),
                            React.DOM.br(null, null),*/
                            React.DOM.br(null, null),
                            React.DOM.span(null, React.DOM.label({}, "IPv6 address:")),
                            React.DOM.br(null, null),
                            React.DOM.span(null, ipV6Address.address),
                            React.DOM.br(null, null),
                            /*React.DOM.span(null, ipV6Address.broadcast),
                            React.DOM.br(null, null),*/
                        ]
                    )
                } else {
                    return React.DOM.div(
                        null, ""
                    )
                }
            }
        });
    }

})();