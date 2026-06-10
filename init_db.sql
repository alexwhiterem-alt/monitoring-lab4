-- Таблица с информацией об ОС
CREATE TABLE IF NOT EXISTS os_info (
    id SERIAL PRIMARY KEY,
    asset_id UUID DEFAULT gen_random_uuid(),
    name VARCHAR(100),
    version VARCHAR(100),
    arch VARCHAR(50),
    os_id VARCHAR(50),
    version_id VARCHAR(50),
    description TEXT,
    codename VARCHAR(50),
    collected_at TIMESTAMP DEFAULT NOW()
);

-- Таблица с установленным ПО
CREATE TABLE IF NOT EXISTS packages (
    id SERIAL PRIMARY KEY,
    asset_id UUID,
    name VARCHAR(200),
    version VARCHAR(200),
    arch VARCHAR(50),
    description TEXT,
    size INTEGER,
    collected_at TIMESTAMP DEFAULT NOW()
);

-- Таблица уязвимостей
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    vuln_id VARCHAR(100),
    severity VARCHAR(50),
    summary TEXT,
    collected_at TIMESTAMP DEFAULT NOW()
);

-- Таблица связи ПО и уязвимостей
CREATE TABLE IF NOT EXISTS package_vulnerabilities (
    id SERIAL PRIMARY KEY,
    package_name VARCHAR(200),
    package_version VARCHAR(200),
    vuln_id VARCHAR(100),
    ecosystem VARCHAR(50),
    collected_at TIMESTAMP DEFAULT NOW()
);