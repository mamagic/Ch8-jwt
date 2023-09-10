import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { OAuthModule } from 'angular-oauth2-oidc';
import { HTTP_INTERCEPTORS } from '@angular/common/http';

// Components
import { AppComponent } from './app.component';
import { HeaderComponent } from './header/header.component';
import { FooterComponent } from './footer/footer.component';
import { HomeComponent } from './home/home.component';
import { LoginComponent } from './login/login.component';
import { RegistryComponent } from './registry/registry.component';
import { RecentTacosComponent } from './recents/recents.component';
import { SpecialsComponent } from './specials/specials.component';
import { CloudTitleComponent } from './cloud-title/cloudtitle.component';
import { DesignComponent } from './design/design.component';
import { CartComponent } from './cart/cart.component';
import { LocationsComponent } from './locations/locations.component';
import { GroupBoxComponent } from './group-box/groupbox.component';
import { BigButtonComponent } from './big-button/bigbutton.component';
import { LittleButtonComponent } from './little-button/littlebutton.component';
import { ReactiveFormsModule } from '@angular/forms';

//Intercepter
import { AuthInterceptor } from './login/AuthInterceptor';

// Services
import { ApiService } from './api/ApiService';
import { CartService } from './cart/cart-service';
import { RecentTacosService } from './recents/RecentTacosService';

// Pipes
import { NonWrapsPipe } from './recents/NonWrapsPipe';
import { WrapsPipe } from './recents/WrapsPipe';

// Routes
import { routes } from './app.routes';

@NgModule({
  declarations: [
    AppComponent,
    HeaderComponent,
    FooterComponent,
    HomeComponent,
    LoginComponent,
    RegistryComponent,
    RecentTacosComponent,
    SpecialsComponent,
    LocationsComponent,
    CloudTitleComponent,
    DesignComponent,
    CartComponent,
    GroupBoxComponent,
    BigButtonComponent,
    LittleButtonComponent,
    NonWrapsPipe,
    WrapsPipe
  ],
  imports: [
    BrowserModule,
    HttpClientModule,
    FormsModule,
    RouterModule.forRoot(routes),
    OAuthModule.forRoot(),
    ReactiveFormsModule
  ],
  providers: [
    ApiService,
    CartService,
    RecentTacosService,
     {
       provide: HTTP_INTERCEPTORS,
       useClass: AuthInterceptor,
       multi: true
     }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
