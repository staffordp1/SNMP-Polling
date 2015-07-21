--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET client_encoding = 'SQL_ASCII';
SET standard_conforming_strings = off;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET escape_string_warning = off;

--
-- Name: plpgsql; Type: PROCEDURAL LANGUAGE; Schema: -; Owner: nacmgr
--

CREATE PROCEDURAL LANGUAGE plpgsql;

ALTER PROCEDURAL LANGUAGE plpgsql OWNER TO nacmgr;

SET search_path = public, pg_catalog;

--
-- Name: ins_function(); Type: FUNCTION; Schema: public; Owner: nacmgr
--

SET default_tablespace = '';
SET default_with_oids = false;

--
-- Name: ignore_ports; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE ignore_ports (
    port character varying(16) NOT NULL,
    l2_ip_addr character varying(64) NOT NULL
);


ALTER TABLE public.ignore_ports OWNER TO nacmgr;

--
-- Name: contact_list; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE contact_list (
    contact character varying(64) NOT NULL,
    description character varying(128),
    pager character varying(64),
    email character varying(64),
    phone character varying(64),
    cell character varying(64)
);


ALTER TABLE public.contact_list OWNER TO nacmgr;

--
-- Name: history_ips; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE history_ips (
    ip_addr character varying(64) NOT NULL,
    poll_id integer NOT NULL
);


ALTER TABLE public.history_ips OWNER TO nacmgr;

--
-- Name: l2_id; Type: SEQUENCE; Schema: public; Owner: nacmgr
--

CREATE SEQUENCE l2_id
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


ALTER TABLE public.l2_id OWNER TO nacmgr;

--
-- Name: l2_networks; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE l2_networks (
    l2_id integer NOT NULL,
    l2_ip_addr character varying(64) NOT NULL,
    vlan_id integer NOT NULL
);


ALTER TABLE public.l2_networks OWNER TO nacmgr;

--
-- Name: l2_status; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE l2_status (
    l2_ip character varying(64) NOT NULL,
    date_entered timestamp without time zone DEFAULT now() NOT NULL,
    poll_status character varying(32),
    poll_begin timestamp without time zone,
    poll_end timestamp without time zone,
    previous_poll_status character varying(32),
    previous_poll_date timestamp without time zone,
    snmp_status character varying(16),
    cdp_status character varying(16),
    ssh_status character varying(16),
    ssh_status_date timestamp without time zone,
    snmp_status_date timestamp without time zone,
    cdp_status_date timestamp without time zone,
    ignore_port_status character varying(32),
    ignore_port_status_date timestamp without time zone
);


ALTER TABLE public.l2_status OWNER TO nacmgr;

--
-- Name: l2_switches; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE l2_switches (
    l2_ip_addr character varying(64) NOT NULL,
    l2_name character varying(64),
    systype integer NOT NULL,
    status character varying(16) DEFAULT 'ACTIVE'::character varying NOT NULL,
    poll_start_time timestamp without time zone,
    poll_end_time timestamp without time zone,
    block_chk character(1),
    status_chk_time timestamp without time zone,
    dev_name character varying(32),
    network_id character varying(8) DEFAULT 'ORNL'::character varying NOT NULL,
    vdc character varying(16)
);


ALTER TABLE public.l2_switches OWNER TO nacmgr;

--
-- Name: l3_routers; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE l3_routers (
    l3_name character varying(32) NOT NULL,
    ip_addr character varying(64) NOT NULL,
    date_last_polled timestamp without time zone,
    outpost character varying(32),
    status character varying(16) NOT NULL,
    network_id character varying(8) NOT NULL,
    date_first_polled timestamp without time zone,
    contact character varying(64),
    systype integer DEFAULT 56,
    ipv6_ready character(1) DEFAULT 'N'::bpchar
);


ALTER TABLE public.l3_routers OWNER TO nacmgr;

--
-- Name: l3_status; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE l3_status (
    l3_name character varying(32) NOT NULL,
    ip_addr character varying(64) NOT NULL,
    date_first_polled timestamp without time zone DEFAULT now(),
    date_last_polled timestamp without time zone DEFAULT now(),
    status character varying(32) DEFAULT 'ACTIVE'::character varying NOT NULL
);


ALTER TABLE public.l3_status OWNER TO nacmgr;

--
-- Name: network_status; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE network_status (
    status character varying(16) NOT NULL,
    description character varying(64) NOT NULL
);


ALTER TABLE public.network_status OWNER TO nacmgr;

--
-- Name: networks; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE networks (
    network_id character varying(8) NOT NULL,
    comm_string character varying(16) NOT NULL,
    rw_comm_string character varying(16),
    enable_pwd character varying(16),
    telnet_pwd character varying(16),
    view_pwd character varying(16),
    user_id character varying(16) DEFAULT 'view'::character varying
);


ALTER TABLE public.networks OWNER TO nacmgr;

--
-- Name: outposts; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE outposts (
    outpost character varying(32) NOT NULL,
    status character varying(16) NOT NULL,
    description character varying(64),
    poll_time integer,
    date_last_polled timestamp without time zone
);


ALTER TABLE public.outposts OWNER TO nacmgr;

--
-- Name: poll_id; Type: SEQUENCE; Schema: public; Owner: nacmgr
--

CREATE SEQUENCE poll_id
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


ALTER TABLE public.poll_id OWNER TO nacmgr;

--
-- Name: polling; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE polling (
    mac character varying(24) NOT NULL,
    port character varying(32) NOT NULL,
    date_first_polled timestamp without time zone NOT NULL,
    date_last_polled timestamp without time zone NOT NULL,
    l2_id integer
);


ALTER TABLE public.polling OWNER TO nacmgr;

--
-- Name: polling_history; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE polling_history (
    poll_id integer NOT NULL,
    mac character varying(24) NOT NULL,
    port character varying(32) NOT NULL,
    vlan character varying(8) NOT NULL,
    l2_ip_addr character varying(64) NOT NULL,
    l3_name character varying(32) NOT NULL,
    date_last_polled timestamp without time zone NOT NULL,
    date_first_polled timestamp without time zone NOT NULL
);


ALTER TABLE public.polling_history OWNER TO nacmgr;

--
-- Name: polling_ips; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE polling_ips (
    ip_addr character varying(64) NOT NULL,
    mac character varying(24) NOT NULL
);


ALTER TABLE public.polling_ips OWNER TO nacmgr;

--
-- Name: vlans; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE vlans (
    vlan_id integer NOT NULL,
    vlan character varying(8) NOT NULL,
    l3_name character varying(32) NOT NULL,
    vlan_name character varying(64),
    status character varying(16) NOT NULL,
    poll_start_time timestamp without time zone,
    poll_end_time timestamp without time zone,
    l2_vlan character varying(8) NOT NULL,
    pz character varying(128) DEFAULT 'A'::bpchar NOT NULL,
    autoblock character(1) DEFAULT '0'::bpchar NOT NULL,
    contact character varying(32),
    is_wireless character(1) DEFAULT 'N'::bpchar
);


ALTER TABLE public.vlans OWNER TO nacmgr;

--
-- Name: systypes; Type: TABLE; Schema: public; Owner: nacmgr; Tablespace: 
--

CREATE TABLE systypes (
    id integer NOT NULL,
    description character varying(64) NOT NULL,
    protocol character varying(8) DEFAULT 'SNMP'::character varying,
    ssh character(1) DEFAULT '1'::bpchar
);


ALTER TABLE public.systypes OWNER TO nacmgr;

--
-- Name: vlan_id; Type: SEQUENCE; Schema: public; Owner: nacmgr
--

CREATE SEQUENCE vlan_id
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


ALTER TABLE public.vlan_id OWNER TO nacmgr;

 create index history_ips_ip on history_ips(ip_addr); 
 create index polling_ips_mac_id1 on polling_ips(mac);
 create index polling_dt2_id4 on polling(date_last_polled);
 create index polling_dt1_id5 on polling(date_first_polled);
 create index polling_id6 on polling(port);
 create index polling_id1 on polling(L2_id);
 create index l2_networks_id1 on l2_networks(l2_ip_addr);
 create index l2_networks_id2 on l2_networks(vlan_id);
 create index L2_switches_id1 on L2_switches(status);
 create index ignore_ports_id1 on ignore_ports(l2_ip_addr);
 create index L3_routers_id2 on L3_routers(network_id);
 create index L3_routers_id3 on L3_routers(outpost);
 create index vlans_id1 on vlans(l3_name);
 create index vlans_id2 on vlans(status);
 create index vlans_id3 on vlans(vlan);

