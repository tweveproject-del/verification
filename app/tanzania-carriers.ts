// Tanzania Mobile Network Carrier Presets, Host Lines, and Verified Sync Profiles

export interface TanzaniaHostLine {
  domain: string;
  category: 'SelfCare & Portal' | 'FinTech & M-Pesa' | 'CDN Front' | 'Gateway';
  tunnelMethod: 'TLS / SNI Spoof' | 'CDN WebSocket' | 'Direct HTTP Payload';
  protocols: string[];
  recommendedPort: number;
  samplePayload: string;
}

export interface TanzaniaVerifiedTemplate {
  title: string;
  format: '.nm' | '.v2box' | '.hc' | '.hat';
  protocol: string;
  description: string;
  rawConfig: string;
}

export interface TanzaniaCarrier {
  id: string;
  name: string;
  brandColor: string;
  pillClass: string;
  badge: string;
  mccMnc: string;
  primaryDns: string;
  secondaryDns: string;
  hostLines: TanzaniaHostLine[];
  templates: TanzaniaVerifiedTemplate[];
}

export const TANZANIA_CARRIERS: TanzaniaCarrier[] = [
  {
    id: 'vodacom',
    name: 'Vodacom Tanzania',
    brandColor: '#e60000',
    pillClass: 'carrier-pill-vodacom',
    badge: 'M-Pesa • 4G / 5G LTE',
    mccMnc: '640-04',
    primaryDns: '196.201.224.2',
    secondaryDns: '196.201.224.3',
    hostLines: [
      {
        domain: 'myvodacom.vodacom.co.tz',
        category: 'SelfCare & Portal',
        tunnelMethod: 'TLS / SNI Spoof',
        protocols: ['NetMod Syna', 'V2Box Reality', 'HA Tunnel', 'HTTP Custom'],
        recommendedPort: 443,
        samplePayload: 'GET / HTTP/1.1[crlf]Host: myvodacom.vodacom.co.tz[crlf]X-Online-Host: myvodacom.vodacom.co.tz[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]',
      },
      {
        domain: 'vodacom.co.tz',
        category: 'Gateway',
        tunnelMethod: 'TLS / SNI Spoof',
        protocols: ['V2Box Reality', 'NetMod Syna', 'WireGuard'],
        recommendedPort: 443,
        samplePayload: 'HEAD / HTTP/1.1[crlf]Host: vodacom.co.tz[crlf]Connection: Keep-Alive[crlf][crlf]',
      },
      {
        domain: 'mpesa.vodacom.co.tz',
        category: 'FinTech & M-Pesa',
        tunnelMethod: 'Direct HTTP Payload',
        protocols: ['HTTP Custom', 'OpenTunnel', 'HTTP Injector'],
        recommendedPort: 80,
        samplePayload: 'GET http://mpesa.vodacom.co.tz/ HTTP/1.1[crlf]Host: mpesa.vodacom.co.tz[crlf]X-Forward-Host: mpesa.vodacom.co.tz[crlf]Connection: Keep-Alive[crlf][crlf]',
      },
      {
        domain: 'vodacom.cloudedge.net',
        category: 'CDN Front',
        tunnelMethod: 'CDN WebSocket',
        protocols: ['VLESS WS', 'VMess WS', 'NetMod'],
        recommendedPort: 443,
        samplePayload: 'GET /vless-ws HTTP/1.1[crlf]Host: vodacom.cloudedge.net[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]',
      },
    ],
    templates: [
      {
        title: 'Vodacom TZ Fast VLESS Reality (V2Box)',
        format: '.v2box',
        protocol: 'VLESS Reality (XTLS)',
        description: 'VLESS Reality tunnel with SNI spoofing on myvodacom.vodacom.co.tz',
        rawConfig: 'vless://93a61219-c703-4f9e-a0e2-6dcfb4c48924@tr-edge.vodatunnel.com:443?security=reality&sni=myvodacom.vodacom.co.tz&fp=chrome&pbk=o_M8eWjW2XmY3-4f9e-a0e2-6dcfb4c48924&sid=6f2a8910&type=tcp&flow=xtls-rprx-vision#Vodacom+TZ+Fast+Cloud',
      },
      {
        title: 'Vodacom NetMod Syna Profile (.nm)',
        format: '.nm',
        protocol: 'NetMod Syna Multi-Protocol',
        description: 'NetMod multi-profile configuration with Vodacom Tanzania cloud group',
        rawConfig: JSON.stringify({
          Common: [
            {
              Protocol: 'vless',
              Remark: '🇹🇿 Vodacom Tanzania VIP Cloud',
              Hostname: 'tz-voda.cloudedge.net',
              Port: 443,
              UserID: '93a61219-c703-4f9e-a0e2-6dcfb4c48924',
              TransferProtocol: 'ws',
              Host: 'myvodacom.vodacom.co.tz',
              Path: '/voda-ws',
              TLSType: 'reality',
              SNI: 'myvodacom.vodacom.co.tz',
              PubKey: 'o_M8eWjW2XmY3-4f9e-a0e2-6dcfb4c48924',
              ShortId: '6f2a8910',
              FingerPrint: 'chrome',
              Alpn: 'h2,http/1.1',
              Flow: 'xtls-rprx-vision',
              Locked: false
            }
          ],
          ServerGroups: [
            {
              Name: '🇹🇿 Vodacom Tanzania Cloud Sync',
              URL: 'https://sync.vpn4pros.com/vodacom-tz'
            }
          ],
          'Version Android': 16,
          'Prevent Root': true,
          'Prevent Wifi': false,
          Expire: '2027-01-01 00:00:00',
          Note: '🇹🇿 Verified Vodacom Tanzania Hostline Configuration'
        }, null, 2),
      }
    ]
  },
  {
    id: 'airtel',
    name: 'Airtel Tanzania',
    brandColor: '#e30613',
    pillClass: 'carrier-pill-airtel',
    badge: 'Airtel Money • 4G LTE',
    mccMnc: '640-05',
    primaryDns: '41.222.180.2',
    secondaryDns: '41.222.180.3',
    hostLines: [
      {
        domain: 'selfcare.airtel.co.tz',
        category: 'SelfCare & Portal',
        tunnelMethod: 'TLS / SNI Spoof',
        protocols: ['NetMod Syna', 'V2Box Reality', 'HA Tunnel', 'HTTP Custom'],
        recommendedPort: 443,
        samplePayload: 'CONNECT [host_port] HTTP/1.1[crlf]Host: selfcare.airtel.co.tz[crlf]X-Forwarded-For: selfcare.airtel.co.tz[crlf]Connection: Keep-Alive[crlf][crlf]',
      },
      {
        domain: 'airtelmoney.airtel.co.tz',
        category: 'FinTech & M-Pesa',
        tunnelMethod: 'Direct HTTP Payload',
        protocols: ['HTTP Custom', 'HTTP Injector', 'OpenTunnel'],
        recommendedPort: 80,
        samplePayload: 'GET http://airtelmoney.airtel.co.tz/ HTTP/1.1[crlf]Host: airtelmoney.airtel.co.tz[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]',
      },
      {
        domain: 'airtel.co.tz',
        category: 'Gateway',
        tunnelMethod: 'TLS / SNI Spoof',
        protocols: ['V2Box Reality', 'NetMod Syna', 'WireGuard'],
        recommendedPort: 443,
        samplePayload: 'GET / HTTP/1.1[crlf]Host: airtel.co.tz[crlf]Connection: Keep-Alive[crlf][crlf]',
      },
    ],
    templates: [
      {
        title: 'Airtel TZ VLESS Cloud Tunnel (V2Box)',
        format: '.v2box',
        protocol: 'VLESS Reality (XTLS)',
        description: 'Airtel Tanzania VLESS Reality with selfcare.airtel.co.tz SNI',
        rawConfig: 'vless://48d39b10-a294-4c91-925a-4e89fbc09281@airtel-edge.tzserver.net:443?security=reality&sni=selfcare.airtel.co.tz&fp=chrome&pbk=a_N9fXkX3YnZ4-5g0f-b1f3-7edf5c559035&sid=7a3b9021&type=tcp#Airtel+TZ+Cloud',
      },
      {
        title: 'Airtel NetMod Syna Config (.nm)',
        format: '.nm',
        protocol: 'NetMod Syna Profile',
        description: 'Airtel Tanzania profile configuration with host line validation',
        rawConfig: JSON.stringify({
          Common: [
            {
              Protocol: 'vless',
              Remark: '🇹🇿 Airtel Tanzania High Speed',
              Hostname: 'tz-airtel.cloudedge.net',
              Port: 443,
              UserID: '48d39b10-a294-4c91-925a-4e89fbc09281',
              TransferProtocol: 'ws',
              Host: 'selfcare.airtel.co.tz',
              Path: '/airtel-ws',
              TLSType: 'reality',
              SNI: 'selfcare.airtel.co.tz',
              PubKey: 'a_N9fXkX3YnZ4-5g0f-b1f3-7edf5c559035',
              ShortId: '7a3b9021',
              FingerPrint: 'chrome',
              Alpn: 'h2,http/1.1',
              Locked: false
            }
          ],
          'Version Android': 16,
          'Prevent Root': false,
          'Prevent Wifi': false,
          Expire: '2027-01-01 00:00:00',
          Note: '🇹🇿 Verified Airtel Tanzania Hostline Configuration'
        }, null, 2),
      }
    ]
  },
  {
    id: 'tigo',
    name: 'Tigo / Yas Tanzania',
    brandColor: '#0072ce',
    pillClass: 'carrier-pill-tigo',
    badge: 'Tigo Pesa • 4G / 5G LTE',
    mccMnc: '640-02',
    primaryDns: '196.43.100.100',
    secondaryDns: '196.43.100.101',
    hostLines: [
      {
        domain: 'tigopesa.tigo.co.tz',
        category: 'FinTech & M-Pesa',
        tunnelMethod: 'Direct HTTP Payload',
        protocols: ['HTTP Custom', 'HA Tunnel', 'OpenTunnel'],
        recommendedPort: 80,
        samplePayload: 'GET / HTTP/1.1[crlf]Host: tigopesa.tigo.co.tz[crlf]X-Online-Host: tigopesa.tigo.co.tz[crlf]User-Agent: TigoPesaApp/5.0[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]',
      },
      {
        domain: 'yas.co.tz',
        category: 'SelfCare & Portal',
        tunnelMethod: 'TLS / SNI Spoof',
        protocols: ['NetMod Syna', 'V2Box Reality', 'HA Tunnel'],
        recommendedPort: 443,
        samplePayload: 'HEAD / HTTP/1.1[crlf]Host: yas.co.tz[crlf]Connection: Keep-Alive[crlf][crlf]',
      },
      {
        domain: 'tigo.co.tz',
        category: 'Gateway',
        tunnelMethod: 'TLS / SNI Spoof',
        protocols: ['V2Box Reality', 'NetMod Syna', 'WireGuard'],
        recommendedPort: 443,
        samplePayload: 'GET / HTTP/1.1[crlf]Host: tigo.co.tz[crlf]Connection: Keep-Alive[crlf][crlf]',
      },
    ],
    templates: [
      {
        title: 'Tigo / Yas TZ VLESS Reality (V2Box)',
        format: '.v2box',
        protocol: 'VLESS Reality (XTLS)',
        description: 'Tigo Tanzania VLESS Reality configured for tigopesa.tigo.co.tz',
        rawConfig: 'vless://71f28c22-b305-4d02-836b-5f90adc10392@tigo-edge.tzserver.net:443?security=reality&sni=tigopesa.tigo.co.tz&fp=chrome&pbk=b_O0gYlY4ZoA5-6h1g-c2g4-8fef6d660146&sid=8b4c0132&type=tcp#Tigo+TZ+Fast+Cloud',
      },
      {
        title: 'Tigo NetMod Syna Config (.nm)',
        format: '.nm',
        protocol: 'NetMod Syna Profile',
        description: 'Tigo Tanzania multi-profile configuration with server groups',
        rawConfig: JSON.stringify({
          Common: [
            {
              Protocol: 'vless',
              Remark: '🇹🇿 Tigo Tanzania Cloud Node',
              Hostname: 'tz-tigo.cloudedge.net',
              Port: 443,
              UserID: '71f28c22-b305-4d02-836b-5f90adc10392',
              TransferProtocol: 'ws',
              Host: 'tigopesa.tigo.co.tz',
              Path: '/tigo-ws',
              TLSType: 'reality',
              SNI: 'tigopesa.tigo.co.tz',
              PubKey: 'b_O0gYlY4ZoA5-6h1g-c2g4-8fef6d660146',
              ShortId: '8b4c0132',
              FingerPrint: 'chrome',
              Alpn: 'h2,http/1.1',
              Locked: false
            }
          ],
          'Version Android': 16,
          'Prevent Root': false,
          'Prevent Wifi': false,
          Expire: '2027-01-01 00:00:00',
          Note: '🇹🇿 Verified Tigo Tanzania Hostline Configuration'
        }, null, 2),
      }
    ]
  },
  {
    id: 'halotel',
    name: 'Halotel Tanzania',
    brandColor: '#ea5b0c',
    pillClass: 'carrier-pill-halotel',
    badge: 'HaloPesa • 4G LTE',
    mccMnc: '640-09',
    primaryDns: '41.79.0.2',
    secondaryDns: '41.79.0.3',
    hostLines: [
      {
        domain: 'halopesa.halotel.co.tz',
        category: 'FinTech & M-Pesa',
        tunnelMethod: 'Direct HTTP Payload',
        protocols: ['HTTP Custom', 'HA Tunnel', 'OpenTunnel'],
        recommendedPort: 80,
        samplePayload: 'GET http://halopesa.halotel.co.tz/ HTTP/1.1[crlf]Host: halopesa.halotel.co.tz[crlf]Connection: Keep-Alive[crlf][crlf]',
      },
      {
        domain: 'halotel.co.tz',
        category: 'Gateway',
        tunnelMethod: 'TLS / SNI Spoof',
        protocols: ['V2Box Reality', 'NetMod Syna', 'WireGuard'],
        recommendedPort: 443,
        samplePayload: 'HEAD / HTTP/1.1[crlf]Host: halotel.co.tz[crlf]Connection: Keep-Alive[crlf][crlf]',
      },
    ],
    templates: [
      {
        title: 'Halotel TZ VLESS Reality (V2Box)',
        format: '.v2box',
        protocol: 'VLESS Reality (XTLS)',
        description: 'Halotel Tanzania VLESS Reality configured for halopesa.halotel.co.tz',
        rawConfig: 'vless://82e39d33-c416-4e13-947c-6e01bec21403@halotel-edge.tzserver.net:443?security=reality&sni=halopesa.halotel.co.tz&fp=chrome&pbk=c_P1hZmZ5ApB6-7i2h-d3h5-9gfg7e771257&sid=9c5d1243&type=tcp#Halotel+TZ+Cloud',
      },
      {
        title: 'Halotel NetMod Syna Config (.nm)',
        format: '.nm',
        protocol: 'NetMod Syna Profile',
        description: 'Halotel Tanzania profile configuration with host line validation',
        rawConfig: JSON.stringify({
          Common: [
            {
              Protocol: 'vless',
              Remark: '🇹🇿 Halotel Tanzania Cloud VIP',
              Hostname: 'tz-halo.cloudedge.net',
              Port: 443,
              UserID: '82e39d33-c416-4e13-947c-6e01bec21403',
              TransferProtocol: 'ws',
              Host: 'halopesa.halotel.co.tz',
              Path: '/halo-ws',
              TLSType: 'reality',
              SNI: 'halopesa.halotel.co.tz',
              PubKey: 'c_P1hZmZ5ApB6-7i2h-d3h5-9gfg7e771257',
              ShortId: '9c5d1243',
              FingerPrint: 'chrome',
              Alpn: 'h2,http/1.1',
              Locked: false
            }
          ],
          'Version Android': 16,
          'Prevent Root': false,
          'Prevent Wifi': false,
          Expire: '2027-01-01 00:00:00',
          Note: '🇹🇿 Verified Halotel Tanzania Hostline Configuration'
        }, null, 2),
      }
    ]
  }
];
