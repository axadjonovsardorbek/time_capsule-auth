// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v5.26.1
// source: milestones.proto

package genproto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	MilestonesService_Create_FullMethodName  = "/time_capsule.MilestonesService/Create"
	MilestonesService_GetById_FullMethodName = "/time_capsule.MilestonesService/GetById"
	MilestonesService_GetAll_FullMethodName  = "/time_capsule.MilestonesService/GetAll"
	MilestonesService_Update_FullMethodName  = "/time_capsule.MilestonesService/Update"
	MilestonesService_Delete_FullMethodName  = "/time_capsule.MilestonesService/Delete"
)

// MilestonesServiceClient is the client API for MilestonesService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MilestonesServiceClient interface {
	Create(ctx context.Context, in *MilestonesCreateReq, opts ...grpc.CallOption) (*Void, error)
	GetById(ctx context.Context, in *ById, opts ...grpc.CallOption) (*MilestonesGetByIdRes, error)
	GetAll(ctx context.Context, in *MilestonesGetAllReq, opts ...grpc.CallOption) (*MilestonesGetAllRes, error)
	Update(ctx context.Context, in *MilestonesUpdateReq, opts ...grpc.CallOption) (*Void, error)
	Delete(ctx context.Context, in *ById, opts ...grpc.CallOption) (*Void, error)
}

type milestonesServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewMilestonesServiceClient(cc grpc.ClientConnInterface) MilestonesServiceClient {
	return &milestonesServiceClient{cc}
}

func (c *milestonesServiceClient) Create(ctx context.Context, in *MilestonesCreateReq, opts ...grpc.CallOption) (*Void, error) {
	out := new(Void)
	err := c.cc.Invoke(ctx, MilestonesService_Create_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *milestonesServiceClient) GetById(ctx context.Context, in *ById, opts ...grpc.CallOption) (*MilestonesGetByIdRes, error) {
	out := new(MilestonesGetByIdRes)
	err := c.cc.Invoke(ctx, MilestonesService_GetById_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *milestonesServiceClient) GetAll(ctx context.Context, in *MilestonesGetAllReq, opts ...grpc.CallOption) (*MilestonesGetAllRes, error) {
	out := new(MilestonesGetAllRes)
	err := c.cc.Invoke(ctx, MilestonesService_GetAll_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *milestonesServiceClient) Update(ctx context.Context, in *MilestonesUpdateReq, opts ...grpc.CallOption) (*Void, error) {
	out := new(Void)
	err := c.cc.Invoke(ctx, MilestonesService_Update_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *milestonesServiceClient) Delete(ctx context.Context, in *ById, opts ...grpc.CallOption) (*Void, error) {
	out := new(Void)
	err := c.cc.Invoke(ctx, MilestonesService_Delete_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MilestonesServiceServer is the server API for MilestonesService service.
// All implementations must embed UnimplementedMilestonesServiceServer
// for forward compatibility
type MilestonesServiceServer interface {
	Create(context.Context, *MilestonesCreateReq) (*Void, error)
	GetById(context.Context, *ById) (*MilestonesGetByIdRes, error)
	GetAll(context.Context, *MilestonesGetAllReq) (*MilestonesGetAllRes, error)
	Update(context.Context, *MilestonesUpdateReq) (*Void, error)
	Delete(context.Context, *ById) (*Void, error)
	mustEmbedUnimplementedMilestonesServiceServer()
}

// UnimplementedMilestonesServiceServer must be embedded to have forward compatible implementations.
type UnimplementedMilestonesServiceServer struct {
}

func (UnimplementedMilestonesServiceServer) Create(context.Context, *MilestonesCreateReq) (*Void, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Create not implemented")
}
func (UnimplementedMilestonesServiceServer) GetById(context.Context, *ById) (*MilestonesGetByIdRes, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetById not implemented")
}
func (UnimplementedMilestonesServiceServer) GetAll(context.Context, *MilestonesGetAllReq) (*MilestonesGetAllRes, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAll not implemented")
}
func (UnimplementedMilestonesServiceServer) Update(context.Context, *MilestonesUpdateReq) (*Void, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Update not implemented")
}
func (UnimplementedMilestonesServiceServer) Delete(context.Context, *ById) (*Void, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Delete not implemented")
}
func (UnimplementedMilestonesServiceServer) mustEmbedUnimplementedMilestonesServiceServer() {}

// UnsafeMilestonesServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to MilestonesServiceServer will
// result in compilation errors.
type UnsafeMilestonesServiceServer interface {
	mustEmbedUnimplementedMilestonesServiceServer()
}

func RegisterMilestonesServiceServer(s grpc.ServiceRegistrar, srv MilestonesServiceServer) {
	s.RegisterService(&MilestonesService_ServiceDesc, srv)
}

func _MilestonesService_Create_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MilestonesCreateReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MilestonesServiceServer).Create(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MilestonesService_Create_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MilestonesServiceServer).Create(ctx, req.(*MilestonesCreateReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _MilestonesService_GetById_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ById)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MilestonesServiceServer).GetById(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MilestonesService_GetById_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MilestonesServiceServer).GetById(ctx, req.(*ById))
	}
	return interceptor(ctx, in, info, handler)
}

func _MilestonesService_GetAll_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MilestonesGetAllReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MilestonesServiceServer).GetAll(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MilestonesService_GetAll_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MilestonesServiceServer).GetAll(ctx, req.(*MilestonesGetAllReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _MilestonesService_Update_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MilestonesUpdateReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MilestonesServiceServer).Update(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MilestonesService_Update_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MilestonesServiceServer).Update(ctx, req.(*MilestonesUpdateReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _MilestonesService_Delete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ById)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MilestonesServiceServer).Delete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MilestonesService_Delete_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MilestonesServiceServer).Delete(ctx, req.(*ById))
	}
	return interceptor(ctx, in, info, handler)
}

// MilestonesService_ServiceDesc is the grpc.ServiceDesc for MilestonesService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var MilestonesService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "time_capsule.MilestonesService",
	HandlerType: (*MilestonesServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Create",
			Handler:    _MilestonesService_Create_Handler,
		},
		{
			MethodName: "GetById",
			Handler:    _MilestonesService_GetById_Handler,
		},
		{
			MethodName: "GetAll",
			Handler:    _MilestonesService_GetAll_Handler,
		},
		{
			MethodName: "Update",
			Handler:    _MilestonesService_Update_Handler,
		},
		{
			MethodName: "Delete",
			Handler:    _MilestonesService_Delete_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "milestones.proto",
}
