import { Controller, Post, Body, Get, UseGuards, Req, SetMetadata } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { AuthGuard } from '@nestjs/passport';
import { GetUser } from './decorators/get-user.decorator';
import { User } from './entities/user.entity';
import { RawHeaderss } from './decorators/raw-headers.decorator';
import { UseRoleGuard } from './guards/use-role.guard';
import { RoleProtected } from './decorators/role-protected.decorator';
import { ValidRoles } from './interfaces/valid-roles';
import { Auth } from './decorators/auth.decorator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @Post('login')
  login(@Body() loginUserDto: LoginUserDto) {
    return this.authService.loginUser(loginUserDto);
  }

  @Get('private')
  @UseGuards(AuthGuard())
  testingPrivateRoute(
    @GetUser() user: User,
    @GetUser('email') userEmail: string,
    @RawHeaderss() rawHeaderss: string[],
  ){
    return {
      ok:true,
      msg:'Ruta privada',
      user,
      userEmail,
      rawHeaderss
    }
  }
  // @SetMetadata('roles',['admin','super-user'])

  @Get('private2')
  @UseGuards(AuthGuard(), UseRoleGuard)
  @RoleProtected(ValidRoles.admin)
  testingPrivateRoute2(@GetUser() user:User){
    return{
      ok:true,
      msg:'Ruta privada 2',
      user,
    }
  }

  @Get('private3')
  @Auth(ValidRoles.admin)
  testingPrivateRoute3(@GetUser() user:User){
    return{
      ok:true,
      msg:'Ruta privada 3',
      user,
    }
  }

}
