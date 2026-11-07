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
  id: string;
  title: string;
  fileName: string;
  carrierId: 'vodacom' | 'airtel' | 'tigo' | 'halotel';
  carrierName: string;
  format: '.nm' | '.v2box' | '.hc' | '.hat' | '.tnl';
  protocol: string;
  hostLineUsed: string;
  description: string;
  expiryDate: string;
  isExpired: boolean;
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
        id: 'voda-v2box-reality',
        title: 'Vodacom Fast VLESS Reality',
        fileName: 'Vodacom_Tanzania_Fast_V2Box.v2box',
        carrierId: 'vodacom',
        carrierName: 'Vodacom Tanzania',
        format: '.v2box',
        protocol: 'VLESS Reality (XTLS)',
        hostLineUsed: 'myvodacom.vodacom.co.tz',
        description: 'VLESS Reality tunnel with SNI spoofing on myvodacom.vodacom.co.tz',
        expiryDate: '2027-01-01',
        isExpired: false,
        rawConfig: 'vless://93a61219-c703-4f9e-a0e2-6dcfb4c48924@tr-edge.vodatunnel.com:443?security=reality&sni=myvodacom.vodacom.co.tz&fp=chrome&pbk=o_M8eWjW2XmY3-4f9e-a0e2-6dcfb4c48924&sid=6f2a8910&type=tcp&flow=xtls-rprx-vision#Vodacom+TZ+Fast+Cloud',
      },
      {
        id: 'voda-netmod-aes',
        title: 'Vodacom NetMod Syna Profile',
        fileName: 'Vodacom_Tanzania_VIP.nm',
        carrierId: 'vodacom',
        carrierName: 'Vodacom Tanzania',
        format: '.nm',
        protocol: 'NetMod Syna AES-256',
        hostLineUsed: 'myvodacom.vodacom.co.tz',
        description: 'NetMod multi-profile encrypted container with Vodacom Tanzania cloud group',
        expiryDate: '2027-01-01',
        isExpired: false,
        rawConfig: 'XjZaldBOd8TdI2eVAjFhxv1VOGjVXbzW3kz576g5Sv1leAuLu66LnGjv33EDJxRHfsnWOwgqoFZP/F7K1sMH4DdmTIqdC4lIAl5/AlLlHxeKdMtDrAqOh1QfQjiJDFPdlJDilBr+LM/NEQkFEJeMEyQ1kRVmsElvRTvUdcsNvHeQsahSn13rdmgnWwvCctWKZIbWZAMPu+NZreeZfZvJuXb8UC1HZVcqSZKSJNZ2amTecGDUWwI3pOCg3J+Wxl6/YNAUln/+6TOimgM4nN32lbUC3MN+MFqVys72RSKMzLC93y4FgGCQlrG/ej8RGUPvzZbJrOus1VO9137Pok5jk8RqH6RR47ggXBi67NJY61ef//EsIRyY/RNpbG3Z44WvbfNDa+HwlLVc3ykrzHn7tkAAb+DTRJ+nMTQlumMqia9w+Zrab7MFju71eOpIhJrkekd9D8Pw6Na6IizLBCOnIDKqeEVnkmmvHUgWSGs9Amkh4DjS78k5RFw/n7jzFq4HHSr5+yVzPI0cIIAewcz83Ct58Mij/9p7GF8OA1b3Ma54f7JOnp0Bc30DQO33WbMnkigL6b4JC/h9kQIKM7mw8MjfnHw575Q3zAVD5RQ0qfPA3PlksWcZdQa/Tq5WOxwEvN98vRzQl91ItJM76WHYvL2R7yDe5xiajCpucaxf+9NQAfr1VKSrPw/bmOdC7rAbC1hCT38eNkKKKKtwLJcTuCN5rPckIAnI2wPFLdf4+gxgwp4seVLLZ/1vTxDB+0rt+bieP9bPqFbQF59aEwueW/vSvhhwV9hbF9tRDX32F+ln1fmESfaTbEO/TmbGiL72z3FNlLNW4gv88MlS/yR096t+8oui0WdtvQUEHZL13tDFL148fbju7Gk2r6NhKLreq2h2JP+UU6DJ8X7fXFsYJx9OxfSX4+VUEDfbDl+Dvt1mIJl6u8mf3F4jUTWTDsu0',
      },
      {
        id: 'voda-hatunnel',
        title: 'Vodacom HA Tunnel Plus Profile',
        fileName: 'Vodacom_Tanzania_HAT.hat',
        carrierId: 'vodacom',
        carrierName: 'Vodacom Tanzania',
        format: '.hat',
        protocol: 'HA Tunnel TNJL Direct',
        hostLineUsed: 'myvodacom.vodacom.co.tz',
        description: 'HA Tunnel Plus carrier profile with myvodacom.vodacom.co.tz spoof',
        expiryDate: '2027-01-01',
        isExpired: false,
        rawConfig: 'hatunnel://voda-tz-tunnel?sni=myvodacom.vodacom.co.tz&port=443',
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
        id: 'airtel-v2box-reality',
        title: 'Airtel TZ VLESS Cloud Tunnel',
        fileName: 'Airtel_Tanzania_Cloud.v2box',
        carrierId: 'airtel',
        carrierName: 'Airtel Tanzania',
        format: '.v2box',
        protocol: 'VLESS Reality (XTLS)',
        hostLineUsed: 'selfcare.airtel.co.tz',
        description: 'Airtel Tanzania VLESS Reality with selfcare.airtel.co.tz SNI',
        expiryDate: '2027-01-01',
        isExpired: false,
        rawConfig: 'vless://48d39b10-a294-4c91-925a-4e89fbc09281@airtel-edge.tzserver.net:443?security=reality&sni=selfcare.airtel.co.tz&fp=chrome&pbk=a_N9fXkX3YnZ4-5g0f-b1f3-7edf5c559035&sid=7a3b9021&type=tcp#Airtel+TZ+Cloud',
      },
      {
        id: 'airtel-netmod-aes',
        title: 'Airtel NetMod Syna Config',
        fileName: 'Airtel_Tanzania_VIP.nm',
        carrierId: 'airtel',
        carrierName: 'Airtel Tanzania',
        format: '.nm',
        protocol: 'NetMod Syna AES-256',
        hostLineUsed: 'selfcare.airtel.co.tz',
        description: 'Airtel Tanzania profile configuration with host line validation',
        expiryDate: '2027-01-01',
        isExpired: false,
        rawConfig: 'XjZaldBOd8TdI2eVAjFhxv1VOGjVXbzW3kz576g5Sv1leAuLu66LnGjv33EDJxRHRvbeZ1ZzbhDN8O9lqrOdcL1VQDEgOqH8uSw7x60iWLxYL2r0/5oMJGgI/GRjbDqSsdHrgmxAhdyMKhNjxzYxFiEbleOOAFUCzZ72DL4uv+gBhnHngbWqbPBglE8gmWH/xs06EIkcaXfeC3qfNQ4FYirwY79U6K0IayTsVoqmtMOTRQzVCnMFs4NwByqLRJC2BZ82UXTTOsK/czgrPwGMYGXI49W5sjUCuZsKS4LZpNqr4IpSBLDPDOUN7s/D0FhY2PROqcrk2/qVXRE0sVMRwR2x8QYfWjkxxzlpUCwFq3LCGhjjNrak5fYbZPoxFDnSFxfDWbx5/0XzsFD+G8hOmEP0wZl3YeZQm/lWMa1czkh4kx+7Mjb9IbiO442cnEO2dsWBfyeLmD9c0x+VEXk1E6AGcfibm7SiviVKAyA1LGqk7s4/ZRVvXetBZCBYbjwY3cnsml9EqUiLUFhK4QJ6D3NcNaoR0Ce3dyJFguzUmgqFo+VxNCbZT/nWUOXGoOwVYMKeLHlSy2f9b08QwftK7fm4nj/Wz6hW0BefWhMLnlujDLM90XMkkDD0l7EHZyg0CJqZU/XQEAqzoe2WJSxARf1d24xBNKvQ7cwIzVQPnODKaVazLX53dtH6JwXlGZMRZv9nUboKmG1bFizQ6C1mAeT0gkE4GHnL3sW11A8Yr1mv0Sk4MRHudi0MhJEbR4DsZiCZervJn9xeI1E1kw7LtA==',
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
        id: 'tigo-v2box-reality',
        title: 'Tigo / Yas TZ VLESS Reality',
        fileName: 'Tigo_Yas_Tanzania_Fast.v2box',
        carrierId: 'tigo',
        carrierName: 'Tigo / Yas Tanzania',
        format: '.v2box',
        protocol: 'VLESS Reality (XTLS)',
        hostLineUsed: 'tigopesa.tigo.co.tz',
        description: 'Tigo Tanzania VLESS Reality configured for tigopesa.tigo.co.tz',
        expiryDate: '2027-01-01',
        isExpired: false,
        rawConfig: 'vless://71f28c22-b305-4d02-836b-5f90adc10392@tigo-edge.tzserver.net:443?security=reality&sni=tigopesa.tigo.co.tz&fp=chrome&pbk=b_O0gYlY4ZoA5-6h1g-c2g4-8fef6d660146&sid=8b4c0132&type=tcp#Tigo+TZ+Fast+Cloud',
      },
      {
        id: 'tigo-netmod-aes',
        title: 'Tigo NetMod Syna Config',
        fileName: 'Tigo_Tanzania_VIP.nm',
        carrierId: 'tigo',
        carrierName: 'Tigo / Yas Tanzania',
        format: '.nm',
        protocol: 'NetMod Syna AES-256',
        hostLineUsed: 'tigopesa.tigo.co.tz',
        description: 'Tigo Tanzania multi-profile configuration with server groups',
        expiryDate: '2027-01-01',
        isExpired: false,
        rawConfig: 'XjZaldBOd8TdI2eVAjFhxv1VOGjVXbzW3kz576g5Sv1leAuLu66LnGjv33EDJxRHVqR3w2NUU6Z+xIV5WAdmuX4qA9XOAY/+MrIoNpzhDTJGZ62L25XIZrQuZ2ygrSgoRH/yEOPxjuhvKDE7rsmhFp9gjK1oE6VGauZDyME1eCekC79tW5G3a+hogboHpWeUkNsKGwKWuXCl9EaM5MBYQ0BpBxUWGjWwVLf3FB+0ytJ550URxZ/6O5QLjpop9GovY9V24kot/KdKSoMPM6cmpJgdAOIkvU8zNknzNjaLF0bkG6I15f3ACexgm+G1tuOeIiTjKmQLd7Y6zpIAAKDAl47EjwvJpspHLaV6aK1ddVegX1BjB3zRFl05zh4DyhBp1qSGQmRXGPSqoRb7Q+MXihaA5HMcGigC2L6lynhmrPZWRLI8TWBBFO9LMjVeQLkCNMRjc8gWJ5BUwVmU3om0eJtg+odeLoFa+dv6TBZ07MTkcqRzvbiDRa5sYdMCeecxcIMJwafVB3DdgM4UTGTmstPXeOO4DbeZGZ0tBNYdoLgcfiIpD/Xn49nIH0stWY+76WQOlqmaJF2IqADCdrJnbnKM3ymTUcU6562rxNm2CxTJKdRN9mT0ntfpl6Eqlu+fkahl/BLQZ2dUtYBcoREvXIPXA7LikAf9V1ciYGvyBolYZju0SQkP7FvY3UaXF1BT0gTkDY1Nl9vBO/CFqq1Ak6bFfXqCe680cwih863xUtDVx50idVHD11yybef5morU',
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
        id: 'halo-v2box-reality',
        title: 'Halotel TZ VLESS Reality',
        fileName: 'Halotel_Tanzania_Fast.v2box',
        carrierId: 'halotel',
        carrierName: 'Halotel Tanzania',
        format: '.v2box',
        protocol: 'VLESS Reality (XTLS)',
        hostLineUsed: 'halopesa.halotel.co.tz',
        description: 'Halotel Tanzania VLESS Reality configured for halopesa.halotel.co.tz',
        expiryDate: '2027-01-01',
        isExpired: false,
        rawConfig: 'vless://82e39d33-c416-4e13-947c-6e01bec21403@halotel-edge.tzserver.net:443?security=reality&sni=halopesa.halotel.co.tz&fp=chrome&pbk=c_P1hZmZ5ApB6-7i2h-d3h5-9gfg7e771257&sid=9c5d1243&type=tcp#Halotel+TZ+Cloud',
      },
      {
        id: 'halo-netmod-aes',
        title: 'Halotel NetMod Syna Config',
        fileName: 'Halotel_Tanzania_VIP.nm',
        carrierId: 'halotel',
        carrierName: 'Halotel Tanzania',
        format: '.nm',
        protocol: 'NetMod Syna AES-256',
        hostLineUsed: 'halopesa.halotel.co.tz',
        description: 'Halotel Tanzania profile configuration with host line validation',
        expiryDate: '2027-01-01',
        isExpired: false,
        rawConfig: 'XjZaldBOd8TdI2eVAjFhxv1VOGjVXbzW3kz576g5Sv1leAuLu66LnGjv33EDJxRHXY86orScukvfhrh4a8wQN0oRvlvMEDbmIrBFXdQCO2WwSvjjdXwukArqoaipn7rW1vX3MI0mfLiGQvJqgEoz9ZcaZ02eEK3jSS1gMFJq0jV0pY4AylJy3f+WPjoJf+G/7Np0xwYJ8EokKZaDkn79aFx8Mv+wEtykQEVIBVK6coJIzVG6UItaO/8ZH12Vre5Ui1kAusL655cTRTKQGgqeM+a8NIXYszdSvgVKoRyp5RUWXky8ovkxJtu+dKYTwMAF1SrlZM0Vn5swknuDAuFBbVJ742jzAbRxQjZGaAxNT5j/zRGH+a24GZv9aQ2ZK6sDLBjrCScu5kvRuZtAswY7rNwuj/4mhmrk8WI1Wj+MA1oM+joMkC42gsajOcO14SkxVeRvm9paMgXuvjgdAULY3Tuq9FhOkA10kt3Zm/V7DbEcZnmadfs36AzeknOl6udGN2LbfQcAtQia+RrgxmvWCkMy/J3VrTxqH7XTxD11DK1yJkZE+EqrBoYW+lstSaW4g49eQa3KL5RWzasT3r/xqHEK7QbHf41b24ZOvGC7YwwYmJd2tUR4vPK6NHRjqMnEZ9X5hEn2k2xDv05mxoi+9s9xTZSzVuIL/PDJUv8kdPerfvKLotFnbb0FBB2S9d7QxS9ePH247uxpNq+jYSi63oaiH7XNlQnQ6K3ZdBscXKuv0Sk4MRHudi0MhJEbR4DsZiCZervJn9xeI1E1kw7LtA==',
      }
    ]
  }
];

export const ALL_ACTIVE_VPN_FILES: TanzaniaVerifiedTemplate[] = TANZANIA_CARRIERS.flatMap(c => c.templates);
