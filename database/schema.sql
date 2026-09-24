-- CyberSOC reference schema (PostgreSQL).
-- Generated from SQLAlchemy models. In practice the backend creates these
-- tables idempotently on startup (see backend/app/main.py lifespan), so this
-- file is documentation / for DBAs, not a migration runner.
--
-- SIMULATION SAFETY: every table below stores fictional training data only.


CREATE TABLE mitre_techniques (
	id SERIAL NOT NULL, 
	technique_id VARCHAR(16) NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	description TEXT NOT NULL, 
	PRIMARY KEY (id)
);


CREATE TABLE scenarios (
	id SERIAL NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	description TEXT NOT NULL, 
	attack_type VARCHAR(120) NOT NULL, 
	difficulty VARCHAR(20) NOT NULL, 
	initial_state JSON NOT NULL, 
	definition JSON NOT NULL, 
	is_active BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id)
);


CREATE TABLE users (
	id SERIAL NOT NULL, 
	name VARCHAR(120) NOT NULL, 
	email VARCHAR(255) NOT NULL, 
	password_hash VARCHAR(255) NOT NULL, 
	role VARCHAR(11) NOT NULL, 
	is_active BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id)
);


CREATE TABLE audit_logs (
	id SERIAL NOT NULL, 
	user_id INTEGER, 
	action VARCHAR(80) NOT NULL, 
	resource VARCHAR(80) NOT NULL, 
	resource_id INTEGER, 
	timestamp TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	meta JSON NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE SET NULL
);


CREATE TABLE scenario_techniques (
	scenario_id INTEGER NOT NULL, 
	technique_id INTEGER NOT NULL, 
	PRIMARY KEY (scenario_id, technique_id), 
	FOREIGN KEY(scenario_id) REFERENCES scenarios (id) ON DELETE CASCADE, 
	FOREIGN KEY(technique_id) REFERENCES mitre_techniques (id) ON DELETE CASCADE
);


CREATE TABLE simulation_sessions (
	id SERIAL NOT NULL, 
	scenario_id INTEGER NOT NULL, 
	analyst_id INTEGER NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	speed FLOAT NOT NULL, 
	started_at TIMESTAMP WITH TIME ZONE, 
	paused_at TIMESTAMP WITH TIME ZONE, 
	paused_total_sec FLOAT NOT NULL, 
	last_materialized_offset FLOAT NOT NULL, 
	fired_rule_ids JSON NOT NULL, 
	completed_at TIMESTAMP WITH TIME ZONE, 
	score JSON, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(scenario_id) REFERENCES scenarios (id) ON DELETE RESTRICT, 
	FOREIGN KEY(analyst_id) REFERENCES users (id) ON DELETE RESTRICT
);


CREATE TABLE events (
	id SERIAL NOT NULL, 
	simulation_id INTEGER NOT NULL, 
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL, 
	event_type VARCHAR(60) NOT NULL, 
	severity VARCHAR(20) NOT NULL, 
	source VARCHAR(255), 
	destination VARCHAR(255), 
	username VARCHAR(255), 
	device VARCHAR(255), 
	message TEXT NOT NULL, 
	meta JSON NOT NULL, 
	offset_sec FLOAT NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(simulation_id) REFERENCES simulation_sessions (id) ON DELETE CASCADE
);


CREATE TABLE incidents (
	id SERIAL NOT NULL, 
	simulation_id INTEGER NOT NULL, 
	analyst_id INTEGER NOT NULL, 
	title VARCHAR(255) NOT NULL, 
	description TEXT NOT NULL, 
	severity VARCHAR(20) NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	resolved_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(simulation_id) REFERENCES simulation_sessions (id) ON DELETE CASCADE, 
	FOREIGN KEY(analyst_id) REFERENCES users (id) ON DELETE RESTRICT
);


CREATE TABLE sim_assets (
	id SERIAL NOT NULL, 
	simulation_id INTEGER NOT NULL, 
	asset_type VARCHAR(20) NOT NULL, 
	identifier VARCHAR(255) NOT NULL, 
	status VARCHAR(40) NOT NULL, 
	meta JSON NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(simulation_id) REFERENCES simulation_sessions (id) ON DELETE CASCADE
);


CREATE TABLE actions (
	id SERIAL NOT NULL, 
	incident_id INTEGER, 
	simulation_id INTEGER NOT NULL, 
	analyst_id INTEGER NOT NULL, 
	action_type VARCHAR(40) NOT NULL, 
	target VARCHAR(255) NOT NULL, 
	result TEXT NOT NULL, 
	timestamp TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(incident_id) REFERENCES incidents (id) ON DELETE SET NULL, 
	FOREIGN KEY(simulation_id) REFERENCES simulation_sessions (id) ON DELETE CASCADE, 
	FOREIGN KEY(analyst_id) REFERENCES users (id) ON DELETE RESTRICT
);


CREATE TABLE alerts (
	id SERIAL NOT NULL, 
	simulation_id INTEGER NOT NULL, 
	event_id INTEGER, 
	rule_id VARCHAR(80), 
	severity VARCHAR(20) NOT NULL, 
	category VARCHAR(80) NOT NULL, 
	title VARCHAR(255) NOT NULL, 
	description TEXT NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(simulation_id) REFERENCES simulation_sessions (id) ON DELETE CASCADE, 
	FOREIGN KEY(event_id) REFERENCES events (id) ON DELETE SET NULL
);


CREATE TABLE incident_alerts (
	incident_id INTEGER NOT NULL, 
	alert_id INTEGER NOT NULL, 
	PRIMARY KEY (incident_id, alert_id), 
	FOREIGN KEY(incident_id) REFERENCES incidents (id) ON DELETE CASCADE, 
	FOREIGN KEY(alert_id) REFERENCES alerts (id) ON DELETE CASCADE
);
