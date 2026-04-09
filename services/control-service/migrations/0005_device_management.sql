-- Device categories (e.g., "GPS Watch", "Wristband", "Smart Cane", "Home Console")
CREATE TABLE IF NOT EXISTS control_app.device_categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    icon TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default categories based on JiAi product catalog
INSERT INTO control_app.device_categories (name, description, icon, sort_order) VALUES
('GPS Watch', 'Wearable GPS watches with health monitoring', 'watch', 1),
('GPS Tracker', 'Compact GPS tracking devices', 'tracker', 2),
('Home Console', 'Stationary smart home devices', 'console', 3),
('Wristband', 'Fitness and health wristbands', 'wristband', 4),
('Smart Cane', 'GPS-enabled walking canes', 'cane', 5)
ON CONFLICT (name) DO UPDATE SET
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    sort_order = EXCLUDED.sort_order,
    status = 'active',
    updated_at = NOW();

-- Device models (e.g., "L16", "L17PRO", "L08P")
CREATE TABLE IF NOT EXISTS control_app.device_models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category_id UUID NOT NULL REFERENCES control_app.device_categories(id),
    model_code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    manufacturer TEXT NOT NULL DEFAULT 'JiAi Medical',
    description TEXT,
    protocol TEXT NOT NULL DEFAULT 'IW' CHECK (protocol IN ('IW', 'GT06', 'OTHER')),
    connectivity TEXT NOT NULL DEFAULT '4G' CHECK (connectivity IN ('4G', '3G', 'WIFI', 'BLE', 'OTHER')),
    features JSONB NOT NULL DEFAULT '[]',
    image_url TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'discontinued', 'coming_soon')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed device models from JiAi catalog
INSERT INTO control_app.device_models (category_id, model_code, name, manufacturer, description, protocol, connectivity, features) VALUES
((SELECT id FROM control_app.device_categories WHERE name = 'GPS Watch'), 'L16',
 'JiAi L16 4G Mini GPS Band', 'JiAi Medical',
 'Mini GPS band with heart rate, SpO2, blood pressure, temperature, fall detection, and SOS',
 'IW', '4G',
 '["gps","heart_rate","spo2","blood_pressure","temperature","steps","fall_detection","sos","geofence","medical_reminder"]'),

((SELECT id FROM control_app.device_categories WHERE name = 'GPS Watch'), 'L17PRO',
 'JiAi L17PRO 4G Dual CPU GPS Band', 'JiAi Medical',
 'Dual CPU GPS band with roaming support, ECG-ready, all health sensors',
 'IW', '4G',
 '["gps","heart_rate","spo2","blood_pressure","temperature","steps","fall_detection","sos","geofence","roaming"]'),

((SELECT id FROM control_app.device_categories WHERE name = 'GPS Watch'), 'L20PRO',
 'JiAi L20PRO Big Battery GPS Band', 'JiAi Medical',
 'Large battery (900mAh) GPS band with IP67 waterproofing and charge base',
 'IW', '4G',
 '["gps","heart_rate","spo2","blood_pressure","temperature","steps","fall_detection","sos","geofence","ip67"]'),

((SELECT id FROM control_app.device_categories WHERE name = 'GPS Watch'), 'L08P',
 'JiAi L08P 4G Round Thin ECG Watch', 'JiAi Medical',
 'Round AMOLED watch with optional ECG, roaming, BLE location',
 'IW', '4G',
 '["gps","heart_rate","spo2","blood_pressure","temperature","steps","fall_detection","sos","geofence","ecg","ble_location"]'),

((SELECT id FROM control_app.device_categories WHERE name = 'GPS Tracker'), 'L15',
 'JiAi L15 4G Mini GPS Tracker', 'JiAi Medical',
 'Compact GPS tracker with IP67, body temperature, BLE 5.2',
 'IW', '4G',
 '["gps","temperature","steps","fall_detection","sos","geofence","ip67","ble"]'),

((SELECT id FROM control_app.device_categories WHERE name = 'Home Console'), 'L04',
 'JiAi L04 4G/WIFI Home Smart Console', 'JiAi Medical',
 'Bedside smart console with 4G/WIFI/BLE, optional blood pressure cuff and sleep monitor',
 'IW', '4G',
 '["sos","blood_pressure","sleep_monitor","wifi","ble","433mhz"]')
ON CONFLICT (model_code) DO UPDATE SET
    category_id = EXCLUDED.category_id,
    name = EXCLUDED.name,
    manufacturer = EXCLUDED.manufacturer,
    description = EXCLUDED.description,
    protocol = EXCLUDED.protocol,
    connectivity = EXCLUDED.connectivity,
    features = EXCLUDED.features,
    status = 'active',
    updated_at = NOW();
