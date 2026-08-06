from opentrons import protocol_api


metadata = {
    "protocolName": "Datalox virtual lifecycle variant fixture",
    "author": "Datalox",
    "description": "Second self-authored protocol with no physical movement.",
    "apiLevel": "2.20",
}


def run(protocol: protocol_api.ProtocolContext) -> None:
    protocol.comment("Datalox virtual lifecycle variant fixture completed.")
