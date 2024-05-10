# coding=utf-8
from allmydata.web.common import abbreviate_size, render_time_delta, render_time_attr
import time

# 获取客户端已经连接的存储节点的个数
def data_connected_storage_servers(client):
    sb = client.get_storage_broker()
    return len(sb.get_connected_servers())


# 获取客户端知道的所有存储节点（包括没有连接上的
def data_known_storage_servers(client):
    sb = client.get_storage_broker()
    return len(sb.get_all_serverids())


# 获取客户端知道的所有存储节点的详细信息
def data_services(client):
    sb = client.get_storage_broker()
    return sorted(sb.get_known_servers(), key=lambda s: s.get_serverid())


# 获取所有introducer详细信息
def data_introducers(client, time=time.time):
    css = client.introducer_connection_statuses()
    introducer_info_list = []
    for i in range(len(css)):
        cs = css[i]
        connected = "yes" if cs.connected else "no"
        since = cs.last_connection_time
        if since is None:
            since = "N/A"
        else:
            since = render_time_delta(since, time())

        last_received = cs.last_received_time
        if last_received is None:
            last_received = "N/A"
        else:
            last_received = render_time_delta(last_received, time())
        summary=''
        if cs.connected:
            summary = cs.summary
        introducer_info = {
            "id": i + 1,
            "connected": connected,
            "last_received": last_received,
            "summary": summary +" "+ since,
        }
        introducer_info_list.append(introducer_info)
    return introducer_info_list


# 获取已经连接的introducer
def data_connected_introducers(client):
    return len([1 for cs in client.introducer_connection_statuses()
                if cs.connected])


# 获取所有的配置的introducer
def data_total_introducers(client):
    return len(client.introducer_connection_statuses())


# 获取客户端节点的nickname
def data_my_nickname(client):
    return client.nickname


# 获取客户端节点的nodeid
def data_my_nodeid(client):
    return client.get_long_tubid()


# 服务器连接详情
def servers_info(client, time=time.time):
    servers = data_services(client)
    server_list = []
    for i in range(len(servers)):
        server = servers[i]
        longname = server.get_longname()
        nickname = server.get_nickname()

        version = "ksf-1"
        avaliable_space = server.get_available_space()
        if avaliable_space is None:
            avaliable_space = "N/A"
        else:
            avaliable_space = abbreviate_size(avaliable_space)
        # 获取连接状态
        cs = server.get_connection_status()
        #
        since = cs.last_connection_time
        if since is None:
            since = "N/A"
        else:
            since = render_time_delta(since, time())
        #
        last_received = cs.last_received_time
        if last_received is None:
            last_received = "N/A"
        else:
            last_received = render_time_delta(last_received, time())

        if cs.connected:
            summary = cs.summary
        connected = "yes" if cs.connected else "no"
        if cs.connected:
            summary = cs.summary
        server_info = {
            "id": i + 1,
            "longname": longname,
            "nickname": nickname,
            "version": version,
            "avaliable": avaliable_space,
            "connected": connected,
            "summary": summary +" "+ since,
            "last_received": last_received,
        }
        server_list.append(server_info)
    return server_list
