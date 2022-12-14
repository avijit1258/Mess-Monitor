package com.messmonitor.serviceuser.utils;

public enum Status {

    SUCCESS("success"),
    ERROR("error");

    private final String value;

    Status(String value){
        this.value = value;
    }

    public String getValue(){
        return this.value;
    }

}