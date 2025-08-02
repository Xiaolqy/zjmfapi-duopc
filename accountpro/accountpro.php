<?php

use think\Db;


function accountpro_call_api($params, $endpoint, $postData = [], $method = 'POST') {
    // 获取API配置
    $api_ip = $params['server_ip'] ?? ($params['ip'] ?? '');
    $api_port = $params['port'] ?? '';
    $api_username = $params['server_username'] ?? ($params['username'] ?? '');
    $api_token = $params['server_password'] ?? ($params['password'] ?? '');
    
    // 验证必要参数
    if (empty($api_ip) || empty($api_port)) {
        return ['status' => 'error', 'message' => 'API IP地址或端口未配置', 'http_code' => 0];
    }
    
    if ($api_username !== 'admin') {
        return ['status' => 'error', 'message' => '接口用户名必须为 "admin"', 'http_code' => 0];
    }
    
    if (empty($api_token)) {
        return ['status' => 'error', 'message' => 'API令牌未配置', 'http_code' => 0];
    }

    // 构建API URL
    $url = "http://{$api_ip}:{$api_port}{$endpoint}";
    $headers = [
        'Content-Type: application/json',
        'Authorization: Bearer ' . $api_token,
    ];

    // 初始化cURL
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    
    // 处理POST数据
    if ($method === 'POST' && !empty($postData)) {
        // 确保密码为字符串
        if (isset($postData['password'])) {
            $postData['password'] = (string)$postData['password'];
        }
        $jsonData = json_encode($postData);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonData);
    }

    // 执行请求
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    // 错误处理
    if ($error) {
        return ['status' => 'error', 'message' => 'API请求失败: ' . $error, 'http_code' => 0];
    }
    
    // 解析响应
    $decoded_response = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return ['status' => 'error', 'message' => 'API返回无效响应', 'http_code' => $http_code, 'raw_response' => $response];
    }
    
    $decoded_response['http_code'] = $http_code;
    return $decoded_response;
}
//模块运行状态
function accountpro_Status($params)
{

    $result['status'] = 'success';
    $result['data']['status'] = 'on';
    $result['data']['des'] = '运行中...';

    return $result;
}

// 模块元数据
function accountpro_MetaData() {
    return [
        'DisplayName' => 'AccountPro账户系统', 
        'APIVersion' => '1.0', 
        'HelpDoc' => 'https://docs.example.com/accountpro'
    ];
}

// 配置选项
function accountpro_ConfigOptions() {
    return [
        [
            'type' => 'text',
            'name' => '用户默认组',
            'description' => '创建用户时分配的默认用户组',
            'placeholder' => 'users',
            'default' => 'users',
            'key' => 'default_group'
        ],
        [
            'type' => 'text',
            'name' => '远程端口',
            'description' => '远程桌面的访问端口（公网）',
            'placeholder' => '3389',
            'default' => '3389',
            'key' => 'service_port'
        ]
    ];
}

// 测试API连接
function accountpro_TestLink($params) {
    $result = accountpro_call_api($params, '/ping', [], 'GET');
    
    if (isset($result['status']) && $result['status'] === 'success') {
        return [
            'status' => 200,
            'data' => [
                'server_status' => 1,
                'msg' => 'API连接成功: ' . ($result['message'] ?? 'API响应正常')
            ]
        ];
    }
    
    $errorMsg = $result['message'] ?? '未知错误';
    return [
        'status' => 200,
        'data' => [
            'server_status' => 0,
            'msg' => 'API连接失败: ' . $errorMsg . ' (HTTP ' . ($result['http_code'] ?? 0) . ')'
        ]
    ];
}

// 前台显示 - 基础版
function accountpro_ClientArea($params) {
    return [];
}

// 创建账户 - 更新dedicatedip字段
function accountpro_CreateAccount($params) {
    $hostId = $params['hostid'] ?? 0;
    if (!$hostId) {
        return ['status' => 'error', 'msg' => '主机ID无效'];
    }
    
    $username = $params['domain'] ?? '';
    $password = $params['password'] ?? '';
    
    if (empty($username)) {
        return ['status' => 'error', 'msg' => '缺少用户名'];
    }
    
    if (empty($password)) {
        return ['status' => 'error', 'msg' => '缺少密码'];
    }
    
    $servicePort = $params['configoptions']['service_port'] ?? '3389';
    
    // 获取服务器主机域名
    $serverHost = $params['server_host'] ?? '';
    
    $postData = [
        'username' => $username,
        'password' => $password,
        'group' => $params['configoptions']['default_group'] ?? 'users'
    ];
    
    $response = accountpro_call_api($params, '/create_user', $postData, 'POST');
    
    if (isset($response['status']) && $response['status'] === 'success') {
        // 更新数据库 - 添加dedicatedip字段
        $updateData = [
            'username' => $username,
            'port' => $servicePort,
            'dedicatedip' => $serverHost, // 更新dedicatedip字段
            'domainstatus' => 'Active'
        ];
        
        Db::name('host')->where('id', $hostId)->update($updateData);
        return ['status' => 'success', 'msg' => '账户创建成功'];
    }
    
    $errorMsg = $response['message'] ?? 'API请求失败';
    
    // 处理特定错误情况
    if (strpos($errorMsg, 'Object of type bytes is not JSON serializable') !== false) {
        // 处理序列化错误 - 添加dedicatedip字段
        $updateData = [
            'username' => $username,
            'password' => $password,
            'port' => $servicePort,
            'dedicatedip' => $serverHost, // 更新dedicatedip字段
            'domainstatus' => 'Active'
        ];
        
        Db::name('host')->where('id', $hostId)->update($updateData);
        return ['status' => 'success', 'msg' => '账户创建成功（忽略序列化错误）'];
    }
    
    if (strpos($errorMsg, '用户已存在') !== false || strpos($errorMsg, 'already exists') !== false) {
        return ['status' => 'error', 'msg' => '账户创建失败: 用户名已存在'];
    }
    
    return ['status' => 'error', 'msg' => '账户创建成功: ' . $errorMsg];
}

// 暂停账户
function accountpro_SuspendAccount($params) {
    $username = $params['username'] ?? '';
    
    if (empty($username)) {
        return ['status' => 'error', 'msg' => '用户名不能为空'];
    }
    
    $response = accountpro_call_api($params, '/suspend_user/' . urlencode($username), [], 'POST');
    
    if (isset($response['status']) && $response['status'] === 'success') {
        Db::name('host')->where('id', $params['hostid'])->update(['domainstatus' => 'Suspended']);
        return ['status' => 'success'];
    }
    
    $errorMsg = $response['message'] ?? 'API请求失败';
    return ['status' => 'error', 'msg' => '账户暂停失败: ' . $errorMsg];
}

// 恢复账户
function accountpro_UnsuspendAccount($params) {
    $username = $params['username'] ?? '';
    
    if (empty($username)) {
        return ['status' => 'error', 'msg' => '用户名不能为空'];
    }
    
    $response = accountpro_call_api($params, '/activate_user/' . urlencode($username), [], 'POST');
    
    if (isset($response['status']) && $response['status'] === 'success') {
        Db::name('host')->where('id', $params['hostid'])->update(['domainstatus' => 'Active']);
        return ['status' => 'success'];
    }
    
    $errorMsg = $response['message'] ?? 'API请求失败';
    return ['status' => 'error', 'msg' => '账户恢复失败: ' . $errorMsg];
}

// 删除账户
function accountpro_TerminateAccount($params) {
    $username = $params['username'] ?? '';
    
    if (empty($username)) {
        return ['status' => 'error', 'msg' => '用户名不能为空'];
    }
    
    $response = accountpro_call_api($params, '/delete_user/' . urlencode($username), [], 'DELETE');
    
    if (isset($response['status']) && $response['status'] === 'success') {
        Db::name('host')->where('id', $params['hostid'])->update(['domainstatus' => 'Terminated']);
        return ['status' => 'success'];
    }
    
    $errorMsg = $response['message'] ?? 'API请求失败';
    return ['status' => 'error', 'msg' => '账户删除失败: ' . $errorMsg];
}

// 占位函数
function accountpro_CrackPassword($params) {
    return ['status' => 'error', 'msg' => '暂不支持的方法'];
}
